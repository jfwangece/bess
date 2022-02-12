#include "nfv_switch.h"

#include <fstream>

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/udp.h"

#define DEFAULT_TRAFFIC_STATS_UPDATE_PERIOD_NS 200000000 // 200 ms
#define DEFAULT_PER_CORE_MIGRATION_PERIOD_US 200000000 // 200 ms
#define DEFAULT_ACTIVE_FLOW_WINDOW_NS 2000000000 // 2000 ms
#define DEFAULT_PACKET_COUNT_THRESH 1000000

namespace {
const uint64_t TIME_OUT_NS = 10ull * 1000 * 1000 * 1000; // 10 seconds
}

const Commands NFVSwitch::cmds = {
    {"get_summary", "EmptyArg", MODULE_CMD_FUNC(&NFVSwitch::CommandGetSummary),
     Command::THREAD_SAFE},
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&NFVSwitch::CommandClear),
     Command::THREAD_UNSAFE},
};

CommandResponse NFVSwitch::Init([[maybe_unused]]const bess::pb::NFVSwitchArg &arg) {
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

  packet_count_thresh_ = DEFAULT_PACKET_COUNT_THRESH;
  if (arg.packet_count_thresh() > 0) {
    packet_count_thresh_ = (uint64_t)arg.packet_count_thresh();
  }

  quadrant_per_core_packet_rate_thresh_ = 0;
  if (arg.packet_rate_thresh() > 0) {
    quadrant_per_core_packet_rate_thresh_ = (uint64_t)arg.packet_rate_thresh();
  }

  quadrant_high_thresh_ = 0.9;
  quadrant_target_thresh_ = 0.85;
  quadrant_low_thresh_ = 0.8;
  quadrant_assign_packet_rate_thresh_ = quadrant_low_thresh_ * quadrant_per_core_packet_rate_thresh_;
  quadrant_migrate_packet_rate_thresh_ = quadrant_high_thresh_ * quadrant_per_core_packet_rate_thresh_;

  ta_flow_count_thresh_ = 0;
  if (arg.flow_count_thresh() > 0) {
    ta_flow_count_thresh_ = arg.flow_count_thresh();
  }

  LOG(INFO) << "Flow assignment thresh:" << quadrant_assign_packet_rate_thresh_;
  LOG(INFO) << "Flow migration thresh:" << quadrant_migrate_packet_rate_thresh_;
  LOG(INFO) << "Bursty flow packet count thresh:" << packet_count_thresh_;

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
  last_update_traffic_stats_ts_ns_ = 0;
  next_epoch_id_ = 0;

  update_traffic_stats_period_ns_ = DEFAULT_TRAFFIC_STATS_UPDATE_PERIOD_NS;
  if (arg.update_stats_period_ns() > 0) {
    update_traffic_stats_period_ns_ = (uint64_t)arg.update_stats_period_ns();
  }

  LOG(INFO) << "Traffic update period:" << update_traffic_stats_period_ns_;

  return CommandSuccess();
}

CommandResponse NFVSwitch::CommandClear(const bess::pb::EmptyArg &) {
  flow_cache_.clear();
  return CommandSuccess();
}

void NFVSwitch::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  using bess::utils::Ethernet;
  using bess::utils::Ipv4;
  using bess::utils::Tcp;
  using bess::utils::Udp;

  Flow flow;
  Tcp *tcp = nullptr;
  Udp *udp = nullptr;

  // We don't use ctx->current_ns here for better accuracy
  curr_ts_ns_ = tsc_to_ns(rdtsc());

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
      if (!process_new_flow(new_rule)) {
        DropPacket(ctx, pkt);
        continue;
      }

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
        pick_next_idle_core();

        it->second.SetAction(false, 0, cpu_cores_[next_idle_core_].nic_addr);
        emitted = true;
      }
    }

    if (emitted) {
      EmitPacket(ctx, pkt, it->second.egress_port_);
    } else {
      DropPacket(ctx, pkt);
    }

    if (tcp != nullptr && tcp->flags & Tcp::Flag::kFin) {
      flow_cache_.erase(it);
      active_flows_ -= 1;
    }
  }
}

bool NFVSwitch::process_new_flow(FlowRoutingRule &rule) {
  pick_next_normal_core();
  if (!is_normal_core(next_normal_core_)) {
    return false;
  }

  rule.SetAction(false, 0, cpu_cores_[next_normal_core_].nic_addr);
  return true;
}

// Load balancing: 1) flow assignment; 2) load rebalancing;
// Flow assignment
void NFVSwitch::pick_next_normal_core() {
  if (load_balancing_op_ == 1) {
    quadrant_lb();
  } else if (load_balancing_op_ == 2) {
    traffic_aware_lb();
  } else {
    default_lb(); // Round-robin
  }
}

void NFVSwitch::pick_next_idle_core() {
  rr_idle_core_index_ = (rr_idle_core_index_ + 1) % idle_core_count_;
  next_idle_core_ = idle_cores_[rr_idle_core_index_];
}

void NFVSwitch::default_lb() {
  update_traffic_stats();

  rr_normal_core_index_ = (rr_normal_core_index_ + 1) % normal_core_count_;
  next_normal_core_ = normal_cores_[rr_normal_core_index_];
}

// For all CPU cores, this algorithm calculates a value that indicates
// 'how far a CPU core is from violating latency SLOs'.
void NFVSwitch::quadrant_lb() {
  if (update_traffic_stats()) {
    // Greedy assignment and flow packing
    next_normal_core_ = quadrant_pick_core();
  }

  // Overload control via flow migration
  quadrant_migrate();
}

void NFVSwitch::quadrant_migrate() {
  for (auto &it : cpu_cores_) {
    if (is_idle_core(it.core_id)) { continue; }

    if (curr_ts_ns_ < it.last_migrating_ts_ns_ + DEFAULT_PER_CORE_MIGRATION_PERIOD_US) {
      continue;
    }

    // if (it.packet_rate >= quadrant_migrate_packet_rate_thresh_) {
    //   uint64_t diff_rate = it.packet_rate - quadrant_assign_packet_rate_thresh_;
    //   uint64_t sum_rate = 0;
    //   size_t remaining_fc = 1 + it.per_flow_packet_counter.size() / 2;

    //   // Migrating some flows from |it|
    //   while (it.per_flow_packet_counter.size() > remaining_fc &&
    //         sum_rate < diff_rate) {
    //     auto flow_it = it.per_flow_packet_counter.begin();
    //     if (flow_it == it.per_flow_packet_counter.end()) {
    //       break;
    //     }

    //     sum_rate += flow_it->second;
    //     int cid = quadrant_pick_core();
    //     migrate_flow(flow_it->first, it.core_id, cid);
    //   }
    // }

    it.last_migrating_ts_ns_ = curr_ts_ns_;
  }
}

int NFVSwitch::quadrant_pick_core() {
  int core_id = 0;
  int max_per_core_packet_rate = -1;
  for (auto &it : cpu_cores_) {
    if (is_idle_core(it.core_id)) { continue; }
    if (it.packet_rate >= quadrant_assign_packet_rate_thresh_) { continue; }

    if (it.packet_rate > max_per_core_packet_rate) {
      max_per_core_packet_rate = it.packet_rate;
      core_id = it.core_id;
    }
  }
  return core_id;
}

void NFVSwitch::migrate_flow(const Flow &f, int from_id, int to_id) {
  auto it = flow_cache_.find(f);
  if (it == flow_cache_.end()) {
    return;
  }

  if (from_id != to_id) {
    it->second.SetAction(false, 0, cpu_cores_[to_id].nic_addr);
    // auto flow_it = cpu_cores_[from_id].per_flow_packet_counter.find(f);
    // if (flow_it != cpu_cores_[from_id].per_flow_packet_counter.end()) {
    //   cpu_cores_[to_id].per_flow_packet_counter.emplace(f, flow_it->second);
    //   cpu_cores_[from_id].per_flow_packet_counter.erase(flow_it);
    // }
  }
}

void NFVSwitch::traffic_aware_lb() {
  update_traffic_stats();

  // Balance the number of active flows among cores
  next_normal_core_ = 0;
  for (auto &it : cpu_cores_) {
    if (is_idle_core(it.core_id)) { continue; }

    if (ta_flow_count_thresh_ > 0 && 
        it.active_flow_count > ta_flow_count_thresh_) { continue; }

    next_normal_core_ = it.core_id;
  }
}

bool NFVSwitch::update_traffic_stats() {
  if (curr_ts_ns_ - last_update_traffic_stats_ts_ns_ < update_traffic_stats_period_ns_) {
    return false;
  }

  last_update_traffic_stats_ts_ns_ = curr_ts_ns_;
  return true;
}

// Scaling: 1) overload detection; 2) CPU core set adjustment;

CommandResponse NFVSwitch::CommandGetSummary(const bess::pb::EmptyArg &) {
  return CommandResponse();
}

ADD_MODULE(NFVSwitch, "nfv_switch", "NFV per-worker software switch")
