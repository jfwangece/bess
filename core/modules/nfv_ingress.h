#ifndef BESS_MODULES_NFV_INGRESS_H_
#define BESS_MODULES_NFV_INGRESS_H_

#include <map>
#include <vector>

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/flow.h"
#include "../utils/ip.h"

using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Ipv4Prefix;
using bess::utils::Flow;
using bess::utils::FlowHash;
using bess::utils::FlowRoutingRule;

class NFVIngress final : public Module {
 public:
  static const Commands cmds;

  NFVIngress() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const bess::pb::NFVIngressArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse CommandAdd(const bess::pb::NFVIngressArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);
  CommandResponse CommandGetSummary(const bess::pb::EmptyArg &arg);

 private:
  bool process_new_flow(FlowRoutingRule &rule);
  // Available per-core packet queues in the cluster
  std::vector<std::string> idle_core_addrs_;
  std::vector<std::string> core_addrs_;
  int work_core_count_ = 0;
  int idle_core_count_ = 0;
  int next_core_ = 0;
  uint64_t packet_count_thresh_;
  // Per-flow connection table
  std::unordered_map<Flow, FlowRoutingRule, FlowHash> flow_cache_;
  // Total number of active flows in the flow cache
  int active_flows_ = 0;
};

#endif // BESS_MODULES_NFV_INGRESS_H_
