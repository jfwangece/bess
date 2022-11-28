#ifndef BESS_MODULES_METRON_INGRESS_H_
#define BESS_MODULES_METRON_INGRESS_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/checksum.h"
#include "../utils/flow.h"
#include "../utils/ip.h"

#include <map>
#include <vector>

#define MaxWorkerCount 3
#define MaxPerWorkerCoreCount 12
#define MaxCoreCount (MaxWorkerCount * MaxPerWorkerCoreCount)

using bess::utils::ChecksumIncrement16;
using bess::utils::ChecksumIncrement32;
using bess::utils::UpdateChecksumWithIncrement;
using bess::utils::UpdateChecksum16;
using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;
using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Flow;
using bess::utils::FlowHash;

class MetronIngress final : public Module {
 public:
  // static const Commands cmds;
  static rte_atomic16_t selected_core_id_;

  // Representing a group of flows
  struct FlowAggregate {
    uint32_t start;
    uint32_t length;
    uint8_t core;

    inline uint32_t Left() { return this->start; }
    inline uint32_t Right() { return (this->start + this->length - 1); }

    FlowAggregate() {
      start = 0; length = 256; core = 0;
    }
    FlowAggregate(uint32_t s, uint32_t l, uint8_t c) {
      start = s; length = l; core = c;
    }
    FlowAggregate(const FlowAggregate& other) {
      start = other.start; length = other.length; core = other.core;
    }
    bool operator==(const FlowAggregate& other) const {
      return (this->start == other.start) && (this->length == other.length);
    }
  };

  MetronIngress() : Module() {
    max_allowed_workers_ = Worker::kMaxWorkers;
  }

  CommandResponse Init(const bess::pb::MetronIngressArg& arg);
  void DeInit() override;

  void MetronProcessOverloads();
  void QuadrantProcessOverloads();

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

 private:
  uint8_t GetFreeCore();

  // 0: Metron; 1: Quadrant
  int mode_;

  // 1: in lb (aware of overloads);
  // 2: in lb (after the new flow rule is effective)
  uint32_t lb_stage_;

  int rewrite_ = 0;
  be32_t ip_mask_;
  be16_t tcp_port_mask_;

  uint64_t last_update_ts_;

  uint32_t pkt_rate_thresh_;

  // Workers in the cluster (for routing)
  std::vector<Ethernet::Address> macs_;
  std::vector<be32_t> ips_;

  /// Metron
  // All existing flow aggregates in the cluster
  std::vector<FlowAggregate> flow_aggregates_;

  // Per-flow-aggregate connection table
  // [0, 255] -> cpu core index
  uint8_t flow_id_to_core_[256];
  std::map<uint32_t, uint8_t> flow_to_core_;

  // Quadrant
  std::map<uint32_t, uint8_t> flow_cache_;
  std::set<uint32_t> quadrant_per_core_flow_ids_[MaxCoreCount];

  // Common
  bool in_use_cores_[MaxCoreCount] = {false};
  bool is_overloaded_cores_[MaxCoreCount] = {false};

  // For monitoring
  uint32_t per_core_pkt_cnts_[MaxCoreCount];
  uint32_t per_flow_id_pkt_cnts_[256];
};

#endif  // BESS_MODULES_METRON_INGRESS_H_
