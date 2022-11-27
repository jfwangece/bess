#ifndef BESS_MODULES_METRON_INGRESS_H_
#define BESS_MODULES_METRON_INGRESS_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/checksum.h"
#include "../utils/flow.h"
#include "../utils/ip.h"

#include <map>
#include <vector>

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

  // Representing a group of flows
  struct FlowAggregate {
    uint32_t start;
    uint32_t end;
    int core;

    FlowAggregate() {
      start = 0; end = 255; core = 0;
    }
    FlowAggregate(uint32_t s, uint32_t l, int c) {
      start = s; end = s + l; core = c;
    }
    FlowAggregate(const FlowAggregate& other) {
      start = other.start; end = other.end; core = other.core;
    }
    bool operator==(const FlowAggregate& other) const {
      return (this->start == other.start) && (this->end == other.end);
    }
  };

  MetronIngress() : Module() {
    max_allowed_workers_ = Worker::kMaxWorkers;
  }

  CommandResponse Init(const bess::pb::MetronIngressArg& arg);
  void DeInit() override;

  void ProcessOverloads();

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

 private:
  int GetFreeCore();

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

  // All existing flow aggregates in the cluster
  std::vector<FlowAggregate> flow_aggregates_;

  // Per-flow-aggregate connection table
  // [0, 255] -> cpu core index
  int flow_id_to_core_[256];
  std::map<uint32_t, int> flow_to_core_;

  bool in_use_cores_[64] = {false};
  bool is_overloaded_cores_[64] = {false};

  // For monitoring
  uint32_t per_core_pkt_cnts_[64];
  uint32_t per_flow_id_pkt_cnts_[256];
};

#endif  // BESS_MODULES_METRON_INGRESS_H_
