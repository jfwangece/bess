#include "flow_limiter.h"

#include <algorithm>
#include "../utils/common.h"
#include "../utils/endian.h"
#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/time.h"
#include "../utils/udp.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;
using bess::utils::Udp;

void FlowLimiter::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  uint64_t now = rdtsc();

  for (int i = 0; i < cnt; ++i) {
    bess::Packet *pkt = batch->pkts()[i];
    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);

    // ip->header_length (1 word = 4 bytes)
    size_t ip_hdr_len = (ip->header_length) << 2;
    if (ip->protocol == Ipv4::Proto::kTcp) {
      Tcp *tcp = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_hdr_len);
      new_flow_ = std::make_tuple(ip->src, ip->dst, ip->protocol, tcp->src_port, tcp->dst_port);
    } else if (ip->protocol == Ipv4::Proto::kUdp) {
      Udp *udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) + ip_hdr_len);
      new_flow_ = std::make_tuple(ip->src, ip->dst, ip->protocol, udp->src_port, udp->dst_port);
    } else {
      continue;
    }

    auto it = map_flow_to_counter_.find(new_flow_);
    if (count_new_flows_ < num_flows_) {
      if (it == map_flow_to_counter_.end()) {
        // A new flow.
        map_flow_to_counter_[new_flow_] = PerFlowCounter(1, now);
        count_new_flows_ += 1;
      } else {
        (it->second).pkt_cnt += 1;
        (it->second).last_pkt_tsc = now;
      }

      EmitPacket(ctx, pkt, 0);
    } else {
      if (it == map_flow_to_counter_.end()) {
        // We've got enough flows, so drop this one.
        DropPacket(ctx, pkt);
      } else {
        (it->second).pkt_cnt += 1;
        (it->second).last_pkt_tsc = now;
        EmitPacket(ctx, pkt, 0);
      }
    }
  }
}

CommandResponse FlowLimiter::Init(const bess::pb::FlowLimiterArg &arg) {
  map_flow_to_counter_.clear();

  if (arg.num_flows() > 0) {
    num_flows_ = arg.num_flows();
  }
  count_new_flows_ = 0;
  return CommandSuccess();
}

ADD_MODULE(FlowLimiter, "FlowLimiter",
            "Control the number of flows that go through this module")
