#include "nfv_ingress.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/udp.h"

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
  idle_core_count_ = 0;
  if (arg.idle_core_count() > 0) {
    idle_core_count_ = (int)arg.idle_core_count();
  }
  for (int i = 0; i < idle_core_count_; i++) {
    idle_core_addrs_.push_back(arg.core_addrs(i));
  }

  work_core_count_ = arg.core_addrs_size() - idle_core_count_;
  for (int i = 0; i < work_core_count_; i++) {
    core_addrs_.push_back(arg.core_addrs(idle_core_count_ + i));
  }

  for (int i = 0; i < arg.core_addrs_size(); i++) {
    per_core_stats_.emplace(arg.core_addrs(i), WorkerCore{});
  }

  packet_count_thresh_ = 10000000;
  if (arg.packet_count_thresh() > 0) {
    packet_count_thresh_ = (uint64_t)arg.packet_count_thresh();
  }

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

  uint64_t now = ctx->current_ns;
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
      if (now >= it->second.ExpiryTime()) { // an outdated flow
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
          std::piecewise_construct, std::make_tuple(flow), std::make_tuple(new_rule));
      active_flows_ += 1;

      emitted = true;
    }
    it->second.SetExpiryTime(now + TIME_OUT_NS);
    it->second.packet_count_ += 1;

    // Handle bursty flows
    if (it->second.packet_count_ > packet_count_thresh_) {
      if (idle_core_count_ <= 0) { // No reserved cores
        emitted = false;
      } else {
        it->second.SetAction(false, 0, idle_core_addrs_[0]);
        emitted = true;
      }
    }

    if (emitted) {
      eth->dst_addr = it->second.encoded_mac_;
      per_core_stats_[it->second.egress_mac_].active_flows.emplace(it->first, 1);
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
  pick_next_work_core();

  if (next_work_core_ < 0 || next_work_core_ >= work_core_count_) {
    return false;
  }

  rule.SetAction(false, 0, core_addrs_[next_work_core_]);
  return true;
}

void NFVIngress::pick_next_work_core() {
  next_work_core_ = (next_work_core_ + 1) % work_core_count_;
}

CommandResponse NFVIngress::CommandGetSummary(const bess::pb::EmptyArg &) {
  int total_flows = flow_cache_.size();
  int num_flows = 0;
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
