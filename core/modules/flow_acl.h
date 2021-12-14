#ifndef BESS_MODULES_FLOW_ACL_H_
#define BESS_MODULES_FLOW_ACL_H_

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

class FlowACL final : public Module {
 public:
  struct ACLRule {
    bool Match(be32_t sip, be32_t dip, be16_t sport, be16_t dport) const {
      return src_ip.Match(sip) && dst_ip.Match(dip) &&
             (src_port == be16_t(0) || src_port == sport) &&
             (dst_port == be16_t(0) || dst_port == dport);
    }

    Ipv4Prefix src_ip;
    Ipv4Prefix dst_ip;
    be16_t src_port;
    be16_t dst_port;
    bool drop;
  };

  static const Commands cmds;

  FlowACL() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const bess::pb::FlowACLArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse CommandAdd(const bess::pb::FlowACLArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);

 private:
  // The global ACL rule table
  std::vector<ACLRule> rules_;
  // Per-flow connection table
  std::unordered_map<Flow, FlowRecord, FlowHash> flow_cache_;
  // Total number of active flows in the flow cache
  int active_flows_ = 0;
};

#endif  // BESS_MODULES_FLOW_ACL_H_
