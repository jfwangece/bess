#include "flow_lb.h"

#include "../utils/checksum.h"
#include "../utils/ether.h"
#include "../utils/format.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"

using bess::utils::ChecksumIncrement16;
using bess::utils::ChecksumIncrement32;
using bess::utils::UpdateChecksumWithIncrement;
using bess::utils::UpdateChecksum16;

CommandResponse FlowLB::Init(const bess::pb::FlowLBArg &arg) {
  endpoints_.clear();

  for (const auto &host : arg.endpoints()) {
    auto host_addr = host.endpoint();
    be32_t addr;

    bool ret = bess::utils::ParseIpv4Address(host_addr, &addr);
    if (!ret) {
      return CommandFailure(EINVAL, "invalid IP address %s", host_addr.c_str());
    }

    endpoints_.push_back(addr);
  }
  return CommandSuccess();
}

void FlowLB::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  using bess::utils::Ethernet;
  using bess::utils::Ipv4;
  using bess::utils::Tcp;

  gate_idx_t incoming_gate = ctx->current_igate;

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);

    if (ip->protocol != Ipv4::Proto::kTcp) {
      EmitPacket(ctx, pkt, 0);
      continue;
    }

    size_t ip_bytes = ip->header_length << 2;
    Tcp *tcp =
        reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);

    Flow flow;
    flow.src_ip = ip->src;
    flow.dst_ip = ip->dst;
    flow.src_port = tcp->src_port;
    flow.dst_port = tcp->dst_port;

    // Find existing flow, if we have one.
    std::unordered_map<Flow, be32_t, FlowHash>::iterator it =
        flow_cache_.find(flow);

    if (it != flow_cache_.end()) { // an existing flow
      EmitPacket(ctx, pkt, incoming_gate);
    } else { // by default, drop a new flow.
      std::tie(it, std::ignore) = flow_cache_.emplace(
          std::piecewise_construct, std::make_tuple(flow), std::make_tuple());
      
      size_t hashed = rte_hash_crc(&ip->src, sizeof(be32_t), 0);
      size_t endpoint_index = hashed % endpoints_.size();
      it->second = endpoints_[endpoint_index];
      active_flows_ += 1;
    }

    // Modify the packet's destination endpoint, and update IP checksum.
    be32_t before = ip->dst;
    be32_t after = it->second;
    ip->dst = it->second;

    uint32_t l3_increment =
      ChecksumIncrement32(before.raw_value(), after.raw_value());
    ip->checksum = UpdateChecksumWithIncrement(ip->checksum, l3_increment);

    uint32_t l4_increment = l3_increment;
    tcp->checksum = UpdateChecksumWithIncrement(tcp->checksum, l4_increment);

    if (tcp->flags & Tcp::Flag::kFin) {
      flow_cache_.erase(it);
      active_flows_ -= 1;
    }
  }
}

std::string FlowLB::GetDesc() const {
  return bess::utils::Format("%d flows", active_flows_);
}

ADD_MODULE(FlowLB, "flow_lb", "Load Balancer with a per-flow hash table")
