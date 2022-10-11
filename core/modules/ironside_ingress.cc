#include "nfv_ctrl_msg.h"
#include "ironside_ingress.h"

#include "../utils/checksum.h"
#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"

using bess::utils::ChecksumIncrement16;
using bess::utils::ChecksumIncrement32;
using bess::utils::UpdateChecksumWithIncrement;
using bess::utils::UpdateChecksum16;

CommandResponse IronsideIngress::Init(const bess::pb::IronsideIngressArg &arg) {
  endpoints_.clear();
  for (const auto &host : arg.endpoints()) {
    be32_t addr;
    auto host_addr = host.endpoint();
    bool ret = bess::utils::ParseIpv4Address(host_addr, &addr);
    if (!ret) {
      return CommandFailure(EINVAL, "invalid IP address %s", host_addr.c_str());
    }
    endpoints_.push_back(addr);
  }

  ncore_thresh_ = 16;
  if (arg.ncore_thresh() > 0) {
    ncore_thresh_ = arg.ncore_thresh();
  }

  // Init
  flow_cache_.clear();
  return CommandSuccess();
}

void IronsideIngress::DeInit() {
  flow_cache_.clear();
}

void IronsideIngress::UpdateEndpointLB() {
  bess::ctrl::nfvctrl_worker_mu.lock();

  int endpoint_ncore = -1;
  endpoint_id_ = -1;
  for (size_t i = 0; i < endpoints_.size(); i++) {
    if (bess::ctrl::worker_ncore[i] > ncore_thresh_) {
      // Skip overloaded workers
      continue;
    }

    if (i == 0 || bess::ctrl::worker_ncore[i] > endpoint_ncore) {
      endpoint_ncore = bess::ctrl::worker_ncore[i];
      endpoint_id_ = i;
    }
  }

  bess::ctrl::nfvctrl_worker_mu.unlock();
}

void IronsideIngress::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  using bess::utils::Ethernet;
  using bess::utils::Ipv4;
  using bess::utils::Tcp;

  UpdateEndpointLB();

  if (endpoint_id_ == -1) {
    bess::Packet::Free(batch);
    return;
  }

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    if (ip->protocol != Ipv4::Proto::kTcp) {
      DropPacket(ctx, pkt);
      continue;
    }
    size_t ip_bytes = ip->header_length << 2;
    Tcp *tcp =
        reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);

    // Calculate the flow aggregate ID
    // size_t hashed = rte_hash_crc(&ip->src, sizeof(be32_t), 0);
    uint64_t flow_id = ip->dst.value() & 0x03FF;

    auto it = flow_cache_.find(flow_id);
    if (it == flow_cache_.end()) {
      // This is a new flow.
      std::tie(it, std::ignore) = flow_cache_.emplace(
                                  std::piecewise_construct,
                                  std::make_tuple(flow_id), std::make_tuple());
      it->second = endpoints_[endpoint_id_];
    }

    // Update IP dst, checksum, and TCP checksum
    be32_t before = ip->dst;
    be32_t after = it->second;
    ip->dst = it->second;

    uint32_t l3_increment =
      ChecksumIncrement32(before.raw_value(), after.raw_value());
    ip->checksum = UpdateChecksumWithIncrement(ip->checksum, l3_increment);
    uint32_t l4_increment = l3_increment;
    tcp->checksum = UpdateChecksumWithIncrement(tcp->checksum, l4_increment);

    EmitPacket(ctx, pkt);
  }
}

ADD_MODULE(IronsideIngress, "ironside",
           "A ToR-layer ingress with a per-flow-aggregate hash table")
