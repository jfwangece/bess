#include "nfv_ctrl_msg.h"
#include "measure.h"
#include "metron_ingress.h"

#include "../utils/sys_measure.h"

#define MetronLoadBalancePeriodMs 2000

#define QuadrantLoadBalancePeriodMs 300

// In Metron and Quadrant, the system ingress collects per-core
// and per-worker avg packet rates to determine if a CPU core or
// a worker is overloaded. Then, it updates the flow rule at the
// ToR switch to re-balance flows to mitigate the overload event.
// However, the delay of collecting stats and the delay of
// installing a flow rule can be 100s milliseconds.
#define HardwareRuleDelayMs 200

rte_atomic16_t MetronIngress::selected_core_id_;

CommandResponse MetronIngress::Init(const bess::pb::MetronIngressArg& arg) {
  ips_.clear();
  macs_.clear();
  flow_aggregates_.clear();
  flow_to_core_.clear();

  // 0: metron; 1: quadrant;
  mode_ = 0;
  if (arg.mode() > 0) {
    mode_ = arg.mode();
  }
  if (mode_ == 0) {
    bess::ctrl::exp_id = 2;
  } else if (mode_ == 1) {
    bess::ctrl::exp_id = 3;
  }

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

  bess::utils::slo_ns = 1000000; // default: 1 ms
  if (arg.slo_ns() > 0) {
    bess::utils::slo_ns = arg.slo_ns();
  }

  /// Init
  // Metron
  flow_aggregates_.emplace_back(FlowAggregate());
  for (uint32_t i = 0; i < 256; i++) {
    // Initially, all flow aggregates go to core 0.
    flow_id_to_core_[i] = 0;
    per_flow_id_pkt_cnts_[i] = 0;
  }

  // Quadrant
  rte_atomic16_set(&selected_core_id_, 0);

  // Common
  for (uint8_t i = 0; i < MaxCoreCount; i++) {
    quadrant_per_core_flow_ids_[i].clear();
    per_core_pkt_cnts_[i] = 0;
    in_use_cores_[i] = false;
    is_overloaded_cores_[i] = false;
  }
  in_use_cores_[0] = true;

  lb_stage_ = 0;
  last_update_ts_ = tsc_to_ns(rdtsc());

  LOG(INFO) << "metron ingress: pkt thresh " << pkt_rate_thresh_ << ", slo " << bess::utils::slo_ns;

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
  for (uint8_t i = 0; i < MaxCoreCount; i++) {
    quadrant_per_core_flow_ids_[i].clear();
    per_core_pkt_cnts_[i] = 0;
    in_use_cores_[i] = false;
    is_overloaded_cores_[i] = false;
  }
  in_use_cores_[0] = true;

  for (uint32_t i = 0; i < 256; i++) {
    per_flow_id_pkt_cnts_[i] = 0;
  }
}

uint8_t MetronIngress::GetFreeCore() {
  for (uint8_t i = 0; i < MaxCoreCount; i++) {
    if (!in_use_cores_[i]) {
      return i;
    }
  }

  // LOG(INFO) << "No free CPU cores in the cluster!";
  return 255;
}

void MetronIngress::MetronProcessOverloads() {
  uint64_t curr_ts = tsc_to_ns(rdtsc());
  uint64_t time_diff_ms = (curr_ts - last_update_ts_) / 1000000;

  if (lb_stage_ == 0) {
    if (time_diff_ms < MetronLoadBalancePeriodMs) {
      return;
    }

    for (uint8_t i = 0; i < MaxCoreCount; i++) {
      if (!in_use_cores_[i]) {
        continue;
      }
      if (per_core_pkt_cnts_[i] * 1000 / time_diff_ms > pkt_rate_thresh_) {
        is_overloaded_cores_[i] = true;
      }
    }
    lb_stage_ = 1;
  }

  if (lb_stage_ == 1) {
    if (time_diff_ms < MetronLoadBalancePeriodMs + HardwareRuleDelayMs) {
      return;
    }

    for (uint8_t i = 0; i < MaxCoreCount; i++) {
      if (!in_use_cores_[i] || !is_overloaded_cores_[i]) {
        continue;
      }
      // Migrate 50% traffic from this core
      is_overloaded_cores_[i] = false;

      // Search for the flow aggregate
      uint32_t left = 0; uint32_t right = 255; uint32_t length = 256;
      uint8_t org_core = i;
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
      uint8_t new_core = GetFreeCore();

      in_use_cores_[new_core] = true;
      flow_aggregates_.emplace_back(left, new_length, org_core);
      flow_aggregates_.emplace_back(new_left, new_length, new_core);
      for (uint32_t flow_id = new_left; flow_id < new_left + new_length; flow_id++) {
        if (flow_id > 255) {
          LOG(INFO) << "incorrect flow_id " << flow_id;
          break;
        }
        flow_id_to_core_[flow_id] = new_core;
      }

      // Debug info
      LOG(INFO) << "core " << (int)i << " -> " << (int)new_core << ": " << per_core_pkt_cnts_[i] << " | "
                << "[" << left << ", " << new_left - 1 << "] / "
                << "[" << new_left << ", " << right << "]";
    }

    // Debug info
    LOG(INFO) << "total " << flow_aggregates_.size() << " flow aggregates";

    // Reset packet counters
    for (uint8_t i = 0; i < MaxCoreCount; i++) {
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

void MetronIngress::QuadrantProcessOverloads() {
  // Only core 0 works
  if (rewrite_ != 0) {
    return;
  }

  uint64_t curr_ts = tsc_to_ns(rdtsc());
  uint64_t time_diff_ms = (curr_ts - last_update_ts_) / 1000000;
  uint8_t selected_core = rte_atomic16_read(&selected_core_id_);

  // Check overloads and make load balancing changes
  if (lb_stage_ == 0) {
    if (time_diff_ms < QuadrantLoadBalancePeriodMs) { return; }

    bess::ctrl::sys_measure->QuadrantPauseUpdates();
    uint64_t max_delay = 0;
    for (uint8_t i = 0; i < MaxCoreCount; i++) {
      if (bess::ctrl::pc_max_batch_delay[i] > (uint64_t)bess::utils::slo_ns) {
        if (in_use_cores_[i]) {
          is_overloaded_cores_[i] = true;
          LOG(INFO) << "core " << (int)i << " delay: " << bess::ctrl::pc_max_batch_delay[i];
        }
      } else if (bess::ctrl::pc_max_batch_delay[i] < (uint64_t)bess::utils::slo_ns / 2) {
        // pick the core with the highest load among all non-overloaded cores
        if (max_delay == 0 ||
            max_delay < bess::ctrl::pc_max_batch_delay[i]) {
          max_delay = bess::ctrl::pc_max_batch_delay[i];
          selected_core = i;
        }
      }
      // reset
      bess::ctrl::pc_max_batch_delay[i] = 0;
    }
    bess::ctrl::sys_measure->QuadrantUnpauseUpdates();

    if (!in_use_cores_[selected_core]) {
      in_use_cores_[selected_core] = true;
      LOG(INFO) << "core " << (int)selected_core << " is activated";
    } else {
      LOG(INFO) << "core " << (int)selected_core << " is selected";
    }
    rte_atomic16_set(&selected_core_id_, selected_core);
    lb_stage_ = 1;
  }

  // Enforce changes
  if (lb_stage_ == 1) {
    if (time_diff_ms < QuadrantLoadBalancePeriodMs + HardwareRuleDelayMs) { return; }

    for (uint8_t i = 0; i < MaxCoreCount; i++) {
      if (!in_use_cores_[i] || !is_overloaded_cores_[i]) {
        continue;
      }

      // Migrate flows from overloaded CPU cores
      uint8_t org_core = i;
      // uint8_t new_core = GetFreeCore();
      uint8_t new_core = selected_core;
      if (new_core == 255) {
        continue;
      }

      size_t target_flow_count = quadrant_per_core_flow_ids_[org_core].size() / 2;
      if (target_flow_count == 0) {
        continue;
      }

      std::vector<uint32_t> to_move_flows;
      for (auto it : quadrant_per_core_flow_ids_[org_core]) {
        to_move_flows.emplace_back(it);
        if (to_move_flows.size() == target_flow_count) {
          break;
        }
      }
      for (auto flow_id : to_move_flows) {
        quadrant_per_core_flow_ids_[org_core].erase(flow_id);
        quadrant_per_core_flow_ids_[new_core].emplace(flow_id);
        flow_cache_[flow_id] = new_core;
      }
      in_use_cores_[new_core] = true;
      is_overloaded_cores_[org_core] = false;
      is_overloaded_cores_[new_core] = false;

      // Debug info
      LOG(INFO) << "core " << (int)org_core << " overload. " << to_move_flows.size() << " flows migrated to core " << (int)new_core;
    }

    lb_stage_ = 0;
    last_update_ts_ = tsc_to_ns(rdtsc());
  }
}

void MetronIngress::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  if (mode_ == 0) {
    MetronProcessOverloads();
  } else if (mode_ == 1) {
    QuadrantProcessOverloads();
  } else {
    LOG(FATAL) << "unknown core-level ingress mode " << mode_;
  }

  int cnt = batch->cnt();
  uint8_t selected_core = rte_atomic16_read(&selected_core_id_);
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    Tcp* tcp = reinterpret_cast<Tcp *>(ip + 1);
    if (ip->protocol != Ipv4::Proto::kTcp) {
      DropPacket(ctx, pkt);
      continue;
    }

    uint8_t encode = 0;
    uint8_t dst_worker = 0;
    uint8_t dst_core = 0;
    if (mode_ == 0) {
      // |flow_id|: [0, 255]
      uint32_t flow_id = ip->dst.value() & 0xff;
      encode = flow_id_to_core_[flow_id];
      dst_worker = (encode / MaxPerWorkerCoreCount) % MaxWorkerCount;
      dst_core = encode % MaxPerWorkerCoreCount;

      // Monitoring
      per_flow_id_pkt_cnts_[flow_id] += 1;
      per_core_pkt_cnts_[dst_core] += 1;
    } else if (mode_ == 1) {
      // Quadrant
      uint32_t flow_id = (ip->src.value() & 0x0fff0000) + (ip->dst.value() & 0x00000fff);
      auto it = flow_cache_.find(flow_id);
      if (it == flow_cache_.end()) {
        // This is a new flow
        flow_cache_.emplace(flow_id, selected_core);
        quadrant_per_core_flow_ids_[selected_core].emplace(flow_id);
        encode = selected_core;
      } else {
        encode = it->second;
      }

      dst_worker = (encode / MaxPerWorkerCoreCount) % MaxWorkerCount;
      dst_core = encode % MaxPerWorkerCoreCount;
    }

    // Send to core
    eth->dst_addr = macs_[dst_worker];
    be32_t after = ips_[dst_worker];
    ip->dst = after;
    tcp->reserved = encode; // encode
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
