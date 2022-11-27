#include <metron_ingress.h>

#define LoadBalancePeriodMs 2000

// In Metron and Quadrant, the system ingress collects per-core
// and per-worker avg packet rates to determine if a CPU core or
// a worker is overloaded. Then, it updates the flow rule at the
// ToR switch to re-balance flows to mitigate the overload event.
// However, the delay of collecting stats and the delay of
// installing a flow rule can be 100s milliseconds.
#define HardwareRuleDelayMs 200

CommandResponse MetronIngress::Init(const bess::pb::MetronIngressArg& arg) {
  ips_.clear();
  macs_.clear();
  flow_aggregates_.clear();
  flow_to_core_.clear();

  rewrite_ = 0;
  if (arg.rewrite() > 0) {
    rewrite_ = arg.rewrite();
  }
  if (rewrite_ > 0) {
    ip_mask_ = be32_t(0x000000f0 << (2 * rewrite_));;
    tcp_port_mask_ = be16_t(0x1000 << (rewrite_));
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
  }

  pkt_rate_thresh_ = 1000000;
  if (arg.pkt_rate_thresh() > 0) {
    pkt_rate_thresh_ = arg.pkt_rate_thresh();
  }

  // Initially, all flow aggregates go to core 0.
  flow_aggregates_.emplace_back(FlowAggregate());
  for (uint32_t i = 0; i < 256; i++) {
    flow_id_to_core_[i] = 0;
  }

  // Init
  lb_stage_ = 0;
  last_update_ts_ = tsc_to_ns(rdtsc());

  in_use_cores_[0] = true;
  for (int i = 0; i < 64; i++) {
    per_core_pkt_cnts_[i] = 0;
  }
  for (int i = 0; i < 256; i++) {
    per_flow_id_pkt_cnts_[i] = 0;
  }

  LOG(INFO) << "metron ingress: pkt thresh " << pkt_rate_thresh_;

  return CommandSuccess();
}

void MetronIngress::DeInit() {
  flow_aggregates_.clear();
  flow_to_core_.clear();

  // Initially, all flow aggregates go to core 0.
  flow_aggregates_.emplace_back(FlowAggregate());
  for (uint32_t i = 0; i < 256; i++) {
    flow_id_to_core_[i] = 0;
  }

  in_use_cores_[0] = true;
  for (int i = 0; i < 64; i++) {
    per_core_pkt_cnts_[i] = 0;
  }
  for (int i = 0; i < 256; i++) {
    per_flow_id_pkt_cnts_[i] = 0;
  }
}

int MetronIngress::GetFreeCore() {
  for (int i = 0; i < 20; i++) {
    if (!in_use_cores_[i]) {
      return i;
    }
  }
  LOG(FATAL) << 0;
  return 0;
}

void MetronIngress::ProcessOverloads() {
  uint64_t curr_ts = tsc_to_ns(rdtsc());
  uint64_t time_diff_ms = (curr_ts - last_update_ts_) / 1000000;

  if (lb_stage_ == 0) {
    if (time_diff_ms < LoadBalancePeriodMs) {
      return;
    }

    for (int i = 0; i < 20; i++) {
      if (!in_use_cores_[i]) {
        continue;
      }
      if (per_core_pkt_cnts_[i] * 1000 / time_diff_ms > pkt_rate_thresh_) {
        is_overloaded_cores_[i] = 1;
      }
    }
    lb_stage_ = 1;
  }

  if (lb_stage_ == 1) {
    if (time_diff_ms < LoadBalancePeriodMs + HardwareRuleDelayMs) {
      return;
    }

    for (int i = 0; i < 20; i++) {
      if (!in_use_cores_[i] || !is_overloaded_cores_[i]) {
        continue;
      }
      // Migrate 50% traffic from this core
      is_overloaded_cores_[i] = false;

      // Search for the flow aggregate
      uint32_t left = 0; uint32_t right = 255; uint32_t length = 256;
      int org_core = i;
      bool found = false;
      for (auto it = flow_aggregates_.begin(); it != flow_aggregates_.end(); it++) {
        if (it->core == i) {
          left = it->Left();
          length = it->length;
          right = it->Right();
          flow_aggregates_.erase(it);
          found = true;
          break;
        }
      }
      if (!found) {
        continue;
      }

      // Split
      uint32_t new_length = length / 2;
      if (new_length == 0) {
        continue;
      }

      uint32_t new_left = left + new_length;
      int new_core = GetFreeCore();
      in_use_cores_[new_core] = true;
      flow_aggregates_.emplace_back(left, new_length, org_core);
      flow_aggregates_.emplace_back(new_left, new_length, new_core);
      for (uint32_t flow_id = new_left; flow_id < new_length; flow_id++) {
        if (flow_id > 255) {
          LOG(INFO) << "incorrect flow_id " << flow_id;
          break;
        }
        flow_id_to_core_[flow_id] = new_core;
      }

      // Debug info
      LOG(INFO) << "core " << i << " -> " << new_core << ": " << per_core_pkt_cnts_[i] << " | "
                << "[" << left << ", " << new_left - 1 << "] / "
                << "[" << new_left << ", " << right << "]";
    }

    // Debug info
    LOG(INFO) << "total " << flow_aggregates_.size() << " flow aggregates";

    // Reset
    for (int i = 0; i < 64; i++) {
      per_core_pkt_cnts_[i] = 0;
    }
    for (int i = 0; i < 256; i++) {
      per_flow_id_pkt_cnts_[i] = 0;
    }

    // Next epoch
    lb_stage_ = 0;
    last_update_ts_ = tsc_to_ns(rdtsc());
  }
}

void MetronIngress::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  ProcessOverloads();

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    Tcp* tcp = reinterpret_cast<Tcp *>(ip + 1);
    if (ip->protocol != Ipv4::Proto::kTcp) {
      DropPacket(ctx, pkt);
      continue;
    }

    // |flow_id|: [0, 255]
    uint32_t flow_id = ip->dst.value() & 0xff;

    uint32_t dst_worker = 0;
    uint32_t dst_core = flow_id_to_core_[flow_id];

    /// Note: flows must be migrated to achieve overload-control.
    // auto it = flow_to_core_.find(flow_id);
    // if (it != flow_to_core_.end()) {
    //   dst_core = it->second;
    // } else {
    //   dst_core = flow_id_to_core_[flow_id];
    //   flow_to_core_.emplace(flow_id, dst_core);
    // }

    per_flow_id_pkt_cnts_[flow_id] += 1;
    per_core_pkt_cnts_[dst_core] += 1;

    // Send to core
    eth->dst_addr = macs_[dst_worker];
    be32_t after = ips_[dst_worker];
    ip->dst = after;
    tcp->reserved = dst_core; // encode
    if (rewrite_ > 0) {
      // ip->src = ip->src | ip_mask_;
      tcp->src_port = tcp->dst_port | tcp_port_mask_;
      tcp->dst_port = tcp->dst_port | tcp_port_mask_;
    }
    tcp->checksum = CalculateIpv4TcpChecksum(*ip, *tcp);
    ip->checksum = CalculateIpv4Checksum(*ip);

    EmitPacket(ctx, pkt);
  }
}

ADD_MODULE(MetronIngress, "metron",
           "A ToR-layer ingress with a per-flow-aggregate hash table")
