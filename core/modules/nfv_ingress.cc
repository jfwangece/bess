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
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&NFVIngress::CommandClear),
     Command::THREAD_UNSAFE}};

CommandResponse NFVIngress::Init([[maybe_unused]]const bess::pb::NFVIngressArg &arg) {
  core_count_ = arg.core_addrs_size();
  for (int i = 0; i < core_count_; i++) {
    core_addrs_.push_back(arg.core_addrs(i));
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
        eth->dst_addr = it->second.encoded_mac_;
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
      eth->dst_addr = it->second.encoded_mac_;
    }
    it->second.SetExpiryTime(now + TIME_OUT_NS);

    if (!emitted) {
      DropPacket(ctx, pkt);
    } else {
      EmitPacket(ctx, pkt, 0);
    }

    if (tcp != nullptr && tcp->flags & Tcp::Flag::kFin) {
      flow_cache_.erase(it);
      active_flows_ -= 1;
    }
  }
}

bool NFVIngress::process_new_flow(FlowRoutingRule &rule) {
  if (next_core_ < 0 || next_core_ >= core_count_) {
    return false;
  }

  rule.encoded_mac_.FromString(core_addrs_[next_core_]);
  next_core_ = (next_core_ + 1) % core_count_;
  return true;
}

ADD_MODULE(NFVIngress, "nfv_ingress", "NFV controller with a per-flow hash table")
