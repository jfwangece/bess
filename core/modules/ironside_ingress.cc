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
  bess::ctrl::exp_id = 0;

  // Init
  flow_cache_.clear();
  ips_.clear();
  macs_.clear();
  pkt_cnts_.clear();

  rewrite_ = 0;
  if (arg.rewrite() > 0) {
    rewrite_ = arg.rewrite();
  }
  if (rewrite_ > 0) {
    ip_mask_ = be32_t(0x000000f0 << (2 * rewrite_));;
    tcp_port_mask_ = be16_t(0x1000 << (rewrite_));
  }

  mode_ = 0;
  if (arg.mode() > 0) {
    mode_ = arg.mode();
  }

  for (const auto &host : arg.endpoints()) {
    macs_.push_back(Ethernet::Address(host.mac()));

    be32_t addr;
    auto host_addr = host.ip();
    bool ret = bess::utils::ParseIpv4Address(host_addr, &addr);
    if (!ret) {
      return CommandFailure(EINVAL, "invalid IP address %s", host_addr.c_str());
    }
    ips_.push_back(addr);
    pkt_cnts_.push_back(0);
  }

  ncore_thresh_ = 16;
  if (arg.ncore_thresh() > 0) {
    ncore_thresh_ = arg.ncore_thresh();
  }
  pkt_rate_thresh_ = 500000;
  if (arg.pkt_rate_thresh() > 0) {
    pkt_rate_thresh_ = (uint32_t)arg.pkt_rate_thresh();
  }

  // Init
  last_endpoint_update_ts_ = tsc_to_ns(rdtsc()) - 1000000000;
  for (size_t i = 0; i < pkt_cnts_.size(); i++) {
    pkt_cnts_[i] = 0;
  }

  for (uint32_t i = 0; i < macs_.size(); i++) {
    LOG(INFO) << "worker " << i << ": " << macs_[i].ToString() << ", " << ips_[i].value();
  }
  LOG(INFO) << "mode: " << mode_ << "; ncore thresh=" << ncore_thresh_ << "; rate thresh=" << pkt_rate_thresh_;
  return CommandSuccess();
}

void IronsideIngress::DeInit() {
  flow_cache_.clear();
}

void IronsideIngress::UpdateEndpointLB() {
  uint64_t curr_ts = tsc_to_ns(rdtsc());
  if (curr_ts - last_endpoint_update_ts_ < 1000000000) {
    return;
  }
  last_endpoint_update_ts_ = curr_ts;

  // Do it once
  if (mode_ == 0) { // min core
    endpoint_id_ = -1;
    int endpoint_ncore_cnt = 100;

    bess::ctrl::nfvctrl_worker_mu.lock_shared();
    for (size_t i = 0; i < ips_.size(); i++) {
      // Skip overloaded workers
      if (bess::ctrl::worker_ncore[i] > ncore_thresh_) {
        continue;
      }
      if (bess::ctrl::worker_ncore[i] < endpoint_ncore_cnt) {
        endpoint_ncore_cnt = bess::ctrl::worker_ncore[i];
        endpoint_id_ = i;
      }
    }
    bess::ctrl::nfvctrl_worker_mu.unlock_shared();
  } else if (mode_ == 1) { // min rate
    endpoint_id_ = -1;
    uint32_t endpoint_pkt_rate = 1000000;

    bess::ctrl::nfvctrl_worker_mu.lock_shared();
    for (size_t i = 0; i < ips_.size(); i++) {
      // Skip overloaded workers
      if (pkt_cnts_[i] > pkt_rate_thresh_) {
        continue;
      }
      if (pkt_cnts_[i] < endpoint_pkt_rate) {
        endpoint_pkt_rate = pkt_cnts_[i];
        endpoint_id_ = i;
      }
    }
    bess::ctrl::nfvctrl_worker_mu.unlock_shared();
  } else if (mode_ == 2) { // max core
    endpoint_id_ = -1;
    int endpoint_ncore_cnt = 0;

    bess::ctrl::nfvctrl_worker_mu.lock_shared();
    for (size_t i = 0; i < ips_.size(); i++) {
      // Skip overloaded workers
      if (bess::ctrl::worker_ncore[i] > ncore_thresh_) {
        continue;
      }
      if (pkt_cnts_[i] > pkt_rate_thresh_) {
        continue;
      }
      if (endpoint_ncore_cnt == 0 || bess::ctrl::worker_ncore[i] > endpoint_ncore_cnt) {
        endpoint_ncore_cnt = bess::ctrl::worker_ncore[i];
        endpoint_id_ = i;
      }
    }
    bess::ctrl::nfvctrl_worker_mu.unlock_shared();
  } else if (mode_ == 3) { // max rate
    endpoint_id_ = -1;
    uint32_t endpoint_pkt_rate = 0;

    bess::ctrl::nfvctrl_worker_mu.lock_shared();
    for (size_t i = 0; i < ips_.size(); i++) {
      // Skip overloaded workers
      if (pkt_cnts_[i] > pkt_rate_thresh_) {
        continue;
      }
      if (pkt_cnts_[i] >= endpoint_pkt_rate) {
        endpoint_pkt_rate = pkt_cnts_[i];
        endpoint_id_ = i;
      }
    }
    bess::ctrl::nfvctrl_worker_mu.unlock_shared();
  }

  // Debug log
  LOG(INFO) << endpoint_id_ << ", " << pkt_cnts_[0] << ", " << pkt_cnts_[1] << ", " << pkt_cnts_[2] << ", " << pkt_cnts_[3];

  // Reset
  for (size_t i = 0; i < pkt_cnts_.size(); i++) {
    pkt_cnts_[i] = 0;
  }
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
    uint64_t flow_id = (ip->src.value() & 0x0fff000) + (ip->dst.value() & 0x0fff);

    int dst_worker = 0;
    auto it = flow_cache_.find(flow_id);
    if (it == flow_cache_.end()) {
      if (endpoint_id_ == -1) {
        DropPacket(ctx, pkt);
        continue;
      }
      // This is a new flow.
      flow_cache_.emplace(flow_id, endpoint_id_);
      dst_worker = endpoint_id_;
    } else {
      dst_worker = it->second;
    }

    pkt_cnts_[dst_worker] += 1;
    // Update Ether dst, IP dst, checksum, and TCP checksum
    eth->dst_addr = macs_[dst_worker];
    // be32_t before = ip->dst;
    be32_t after = ips_[dst_worker];
    ip->dst = after;

    if (rewrite_ > 0) {
      // ip->src = ip->src | ip_mask_;
      tcp->src_port = tcp->dst_port | tcp_port_mask_;
      tcp->dst_port = tcp->dst_port | tcp_port_mask_;
    }

    // tcp->checksum = CalculateIpv4TcpChecksum(*ip, *tcp);
    // ip->checksum = CalculateIpv4Checksum(*ip);

    EmitPacket(ctx, pkt);
  }
}

ADD_MODULE(IronsideIngress, "ironside",
           "A ToR-layer ingress with a per-flow-aggregate hash table")
