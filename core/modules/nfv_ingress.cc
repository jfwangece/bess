#include "nfv_ingress.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/udp.h"

#define DEFAULT_TRAFFIC_STATS_UPDATE_PERIOD_NS 100000000
#define DEFAULT_ACTIVE_FLOW_WINDOW_NS 2000000000

namespace {
const uint64_t TIME_OUT_NS = 10ull * 1000 * 1000 * 1000; // 10 seconds
}

const Commands NFVIngress::cmds = {
    {"add", "NFVIngressArg", MODULE_CMD_FUNC(&NFVIngress::CommandAdd),
     Command::THREAD_UNSAFE},
    {"get_summary", "EmptyArg", MODULE_CMD_FUNC(&NFVIngress::CommandGetSummary),
     Command::THREAD_SAFE},
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&NFVIngress::CommandClear),
     Command::THREAD_UNSAFE}};

CommandResponse NFVIngress::Init([[maybe_unused]]const bess::pb::NFVIngressArg &arg) {
  total_core_count_ = arg.core_addrs_size();
  for (int i = 0; i < total_core_count_; i++) {
    cpu_cores_.push_back(WorkerCore{
        core_id: i, worker_port: 0, nic_addr: arg.core_addrs(i)});
    routing_to_core_id_.emplace(arg.core_addrs(i), i);
  }
  assert(total_core_count_ == cpu_cores_.size());

  idle_core_count_ = 0;
  if (arg.idle_core_count() > 0) {
    idle_core_count_ = (int)arg.idle_core_count();
    for (int i = 0; i < idle_core_count_; i++) {
      idle_cores_.push_back(i);
    }
  }

  normal_core_count_ = total_core_count_ - idle_core_count_;
  for (int i = 0; i < normal_core_count_; i++) {
    normal_cores_.push_back(idle_core_count_ + i);
  }
  assert(normal_cores_.size() + idle_cores_.size() == cpu_cores_.size());

  log_core_info();

  packet_count_thresh_ = 10000000;
  if (arg.packet_count_thresh() > 0) {
    packet_count_thresh_ = (uint64_t)arg.packet_count_thresh();
  }

  load_balancing_op_ = 0;
  if (arg.lb() > 0) {
    load_balancing_op_ = arg.lb();
  }
  scale_op_ = 0;
  if (arg.scale() > 0) {
    scale_op_ = arg.scale();
  }

  curr_ts_ns_ = 0;
  last_core_assignment_ts_ns_ = 0;

  return CommandSuccess();
}

CommandResponse NFVIngress::CommandAdd([[maybe_unused]]const bess::pb::NFVIngressArg &arg) {
  Init(arg);
  return CommandSuccess();
}

CommandResponse NFVIngress::CommandClear(const bess::pb::EmptyArg &) {
  flow_cache_.clear();
  return CommandSuccess();
}

void NFVIngress::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  using bess::utils::Ethernet;
  using bess::utils::Ipv4;
  using bess::utils::Tcp;
  using bess::utils::Udp;

  Flow flow;
  Tcp *tcp = nullptr;
  Udp *udp = nullptr;

  curr_ts_ns_ = ctx->current_ns;

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    size_t ip_bytes = ip->header_length << 2;

    if (ip->protocol == Ipv4::Proto::kTcp) {
      tcp = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
      flow.src_ip = ip->src;
      flow.dst_ip = ip->dst;
      flow.src_port = tcp->src_port;
      flow.dst_port = tcp->dst_port;
      flow.proto_ip = ip->protocol;
    } else if (ip->protocol == Ipv4::Proto::kUdp) {
      udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
      flow.src_ip = ip->src;
      flow.dst_ip = ip->dst;
      flow.src_port = udp->src_port;
      flow.dst_port = udp->dst_port;
      flow.proto_ip = ip->protocol;
    } else {
      EmitPacket(ctx, pkt, 0);
      continue;
    }

    // Find existing flow, if we have one.
    std::unordered_map<Flow, FlowRoutingRule, FlowHash>::iterator it =
        flow_cache_.find(flow);

    bool emitted = false;
    if (it != flow_cache_.end()) {
      if (curr_ts_ns_ >= it->second.ExpiryTime()) { // an outdated flow
        flow_cache_.erase(it);
        active_flows_ -= 1;
        it = flow_cache_.end();
      } else { // an existing flow
        emitted = true;
      }
    }

    if (it == flow_cache_.end()) {
      FlowRoutingRule new_rule("02:42:01:c2:02:fe");
      // Assign this flow to a CPU core
      process_new_flow(new_rule);
      std::tie(it, std::ignore) = flow_cache_.emplace(
          std::piecewise_construct,
          std::make_tuple(flow), std::make_tuple(new_rule));
      active_flows_ += 1;

      emitted = true;
    }
    it->second.SetExpiryTime(curr_ts_ns_ + TIME_OUT_NS);
    it->second.packet_count_ += 1;

    // Handle bursty flows
    if (it->second.packet_count_ > packet_count_thresh_) {
      if (idle_core_count_ <= 0) { // No reserved cores
        emitted = false;
      } else {
        it->second.SetAction(false, 0, cpu_cores_[idle_cores_[0]].nic_addr);
        emitted = true;
      }
    }

    if (emitted) {
      eth->dst_addr = it->second.encoded_mac_;
      cpu_cores_[routing_to_core_id_[it->second.egress_mac_]].active_flows.emplace(it->first, curr_ts_ns_);
      EmitPacket(ctx, pkt, 0);
    } else {
      DropPacket(ctx, pkt);
    }

    if (tcp != nullptr && tcp->flags & Tcp::Flag::kFin) {
      flow_cache_.erase(it);
      active_flows_ -= 1;
    }
  }
}

bool NFVIngress::process_new_flow(FlowRoutingRule &rule) {
  pick_next_normal_core();
  if (!is_normal_core(next_normal_core_)) {
    return false;
  }

  rule.SetAction(false, 0, cpu_cores_[next_normal_core_].nic_addr);
  return true;
}

// Load balancing: 1) flow assignment; 2) load rebalancing;
// Flow assignment
void NFVIngress::pick_next_normal_core() {
  // Round-robin
  if (load_balancing_op_ == 0) {
    default_lb();
  } else if (load_balancing_op_ == 1) {
    traffic_aware_lb();
  } else {
    default_lb();
  }
}

void NFVIngress::default_lb() {
  rr_normal_core_index_ = (rr_normal_core_index_ + 1) % normal_core_count_;
  next_normal_core_ = normal_cores_[rr_normal_core_index_];
}

void NFVIngress::traffic_aware_lb() {
  // Balance the number of active flows among cores
  next_normal_core_ = 0;
  size_t min_active_flow_count = 10000000;
  for (auto &it : cpu_cores_) {
    if (is_idle_core(it.core_id)) { continue; }

    if (it.active_flows.size() < min_active_flow_count) {
      min_active_flow_count = it.active_flows.size();
      next_normal_core_ = it.core_id;
    }
  }

  // Remove inactive flows every |traffic-stats-update| period
  if (curr_ts_ns_ - last_core_assignment_ts_ns_ >= DEFAULT_TRAFFIC_STATS_UPDATE_PERIOD_NS) {
    for (auto &it : cpu_cores_) {
      auto flow_it = it.active_flows.begin();
      while (flow_it != it.active_flows.end()) {
        if (curr_ts_ns_ - flow_it->second >= DEFAULT_ACTIVE_FLOW_WINDOW_NS) {
          flow_it = it.active_flows.erase(flow_it);
        } else {
          flow_it++;
        }
      }
    }

    last_core_assignment_ts_ns_ = curr_ts_ns_;
  }
}

// Scaling: 1) overload detection; 2) CPU core set adjustment;

CommandResponse NFVIngress::CommandGetSummary(const bess::pb::EmptyArg &) {
  int total_flows = flow_cache_.size();
  int num_flows = 0; // Count # of bursty flows
  for (auto & x : flow_cache_) {
    if (x.second.packet_count_ > packet_count_thresh_) {
      num_flows += 1;
    }
  }
  std::cout << total_flows;
  std::cout << num_flows;
  std::cout << active_flows_;
  return CommandResponse();
}

ADD_MODULE(NFVIngress, "nfv_ingress", "NFV controller with a per-flow hash table")
