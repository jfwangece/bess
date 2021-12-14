#ifndef BESS_MODULES_FLOW_LB_H_
#define BESS_MODULES_FLOW_LB_H_

#include <map>
#include <vector>
#include <string>

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/flow.h"
#include "../utils/ip.h"

using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Flow;
using bess::utils::FlowHash;

class FlowLB final : public Module {
 public:
  FlowLB() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; active_flows_ = 0; }

  CommandResponse Init(const bess::pb::FlowLBArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  std::string GetDesc() const override;

 private:
  // The global server pool table:
  // A set of available endpoints (IPs) for a certain service
  std::vector<be32_t> endpoints_;
  // Per-flow connection table
  std::unordered_map<Flow, be32_t, FlowHash> flow_cache_;
  // Total number of active flows in the flow cache (connection table)
  int active_flows_ = 0;
};

#endif  // BESS_MODULES_FLOW_LB_H_
