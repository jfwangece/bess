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
  ips_.clear();
  macs_.clear();

  for (const auto &host : arg.endpoints()) {
    macs_.push_back(Ethernet::Address(host.mac()));

    be32_t addr;
    auto host_addr = host.ip();
    bool ret = bess::utils::ParseIpv4Address(host_addr, &addr);
    if (!ret) {
      return CommandFailure(EINVAL, "invalid IP address %s", host_addr.c_str());
    }
    ips_.push_back(addr);
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
  uint64_t curr_ts = tsc_to_ns(rdtsc());
  if (curr_ts - last_endpoint_update_ts_ < 10000000) {
    return;
  }

  // Do it once
  last_endpoint_update_ts_ = curr_ts;
  bess::ctrl::nfvctrl_worker_mu.lock_shared();

  int endpoint_ncore = -1;
  endpoint_id_ = -1;
  for (size_t i = 0; i < ips_.size(); i++) {
    if (bess::ctrl::worker_ncore[i] > ncore_thresh_) {
      // Skip overloaded workers
      continue;
    }

    if (i == 0 || bess::ctrl::worker_ncore[i] > endpoint_ncore) {
      endpoint_ncore = bess::ctrl::worker_ncore[i];
      endpoint_id_ = i;
    }
  }

  bess::ctrl::nfvctrl_worker_mu.unlock_shared();
}

void IronsideIngress::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  UpdateEndpointLB();

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
      if (endpoint_id_ == -1) {
        DropPacket(ctx, pkt);
        continue;
      }
      // This is a new flow.
      std::tie(it, std::ignore) = flow_cache_.emplace(
                                  std::piecewise_construct,
                                  std::make_tuple(flow_id), std::make_tuple());
      it->second = endpoint_id_;
    }

    // Update Ether dst, IP dst, checksum, and TCP checksum
    eth->dst_addr = macs_[it->second];
    be32_t before = ip->dst;
    be32_t after = ips_[it->second];
    ip->dst = after;

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
