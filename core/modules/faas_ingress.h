#ifndef BESS_MODULES_FAASINGRESS_H_
#define BESS_MODULES_FAASINGRESS_H_

#include <vector>

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/ip.h"
#include "../utils/mcslock.h"

using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Ipv4Prefix;

class FaaSIngress final : public Module {
 public:
  // The ingress handles subsequent packet arrivals before the OpenFLow
  // rule is installed.
  enum FlowAction {
    // Drop
    kDrop = 0,
    // Queue
    kQueue,
    // Forward with the same rule.
    kForward,
  };

  struct FlowRule {
  bool Match(be32_t sip, be32_t dip, be16_t sport, be16_t dport) const {
    return src_ip.Match(sip) && dst_ip.Match(dip) &&
       (src_port == be16_t(0) || src_port == sport) &&
       (dst_port == be16_t(0) || dst_port == dport);
  }

  // Match
  Ipv4Prefix src_ip;
  Ipv4Prefix dst_ip;
  be16_t src_port;
  be16_t dst_port;

  // Action for subsequent packets.
  FlowAction action;
  uint egress_port;
  std::string egress_mac;
  };

  static const Commands cmds;

  FaaSIngress() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const bess::pb::FaaSIngressArg &arg);

  void Clear();

  // This function handles the system ingress for FaaS-NFV.
  // For a new flow, it querys the FaaS-Controller to get the egress decision
  // for this flow. Then, the module issues a RPC request to install an
  // OpenFlow rule via the switch controller. All subsequent packets in the
  // flow will be queued by this module before the rule is installed.
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  void process_new_flow();

  CommandResponse CommandAdd(const bess::pb::FaaSIngressArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);

 private:
  std::vector<FlowRule> rules_;

  mcslock lock_;
};

#endif  // BESS_MODULES_FAASINGRESS_H_
