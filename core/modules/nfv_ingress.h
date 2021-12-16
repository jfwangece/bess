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
using bess::utils::FlowRecord;

class NFVIngress final : public Module {
 public:
  static const Commands cmds;

  NFVIngress() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const bess::pb::NFVIngressArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse CommandAdd(const bess::pb::NFVIngressArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);

 private:
  // Per-flow connection table
  std::unordered_map<Flow, FlowRecord, FlowHash> flow_cache_;
  // Total number of active flows in the flow cache
  int active_flows_ = 0;
};

#endif // BESS_MODULES_NFV_INGRESS_H_
