#ifndef BESS_MODULES_FLOW_IP_LOOKUP_H_
#define BESS_MODULES_FLOW_IP_LOOKUP_H_

#include <map>
#include <vector>

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/flow.h"
#include "../utils/ip.h"

using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Flow;
using bess::utils::FlowHash;

class IronsideIngress final : public Module {
 public:
  IronsideIngress() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const bess::pb::IronsideIngressArg &arg);
  void DeInit() override;

  void UpdateEndpointLB();
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

 private:
  // Workers in the cluster.
  std::vector<be32_t> endpoints_;

  // Normal core threshold.
  int ncore_thresh_;
  int endpoint_id_ = 0;

  // Per-flow connection table
  // std::map<Flow, be32_t, FlowHash> flow_cache_;

  // Per-flow-aggregate connection table
  std::map<uint64_t, be32_t> flow_cache_;
};

#endif  // BESS_MODULES_FLOW_IP_LOOKUP_H_
