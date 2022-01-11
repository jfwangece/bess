#ifndef BESS_MODULES_FAAS_INGRESS_H_
#define BESS_MODULES_FAAS_INGRESS_H_

#include <grpc++/grpc++.h>
#include <hiredis/hiredis.h>
#include <deque>
#include <mutex>
#include <vector>
#include <string>

#include "pb/faas_msg.pb.h"
#include "pb/faas_msg.grpc.pb.h"
#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/ether.h"
#include "../utils/flow.h"
#include "../utils/ip.h"
#include "../utils/mcslock.h"

using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Ethernet;
using bess::utils::Ipv4Prefix;
// For migration
using bess::utils::Flow;
using bess::utils::FlowHash;
using bess::utils::FlowRoutingRule;
// For routing
using bess::utils::FlowAction;
using bess::utils::FlowLpmRule;
using bess::utils::kDrop;
using bess::utils::kForward;

class FaaSIngress final : public Module {
 public:
  static const Commands cmds;
  struct PerFlowCounter {
    uint64_t rate;
    uint64_t temp_pkt_cnt;
    uint64_t last_rate_tsc;
  };

  FaaSIngress() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }
  CommandResponse Init(const bess::pb::FaaSIngressArg &arg);
  void Clear();

  // This function handles the system ingress for FaaS-NFV.
  // For a new flow, it querys the FaaS-Controller to get the egress decision
  // for this flow. Then, the module issues a RPC request to install an
  // OpenFlow rule via the switch controller. All subsequent packets in the
  // flow will be queued by this module before the rule is installed.
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse CommandAdd(const bess::pb::FaaSIngressArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);
  CommandResponse CommandUpdate(const bess::pb::FaaSIngressCommandUpdateArg &arg);
  CommandResponse CommandMigrate(const bess::pb::FaaSIngressCommandMigrateArg &arg);

 private:
  bool process_new_flow(Flow &flow, FlowRoutingRule &rule);

  std::string convert_rule_to_string(Flow &flow, FlowRoutingRule &rule);

  // For monitoring per-flow packet rates
  std::unordered_map<Flow, FlowRoutingRule, FlowHash> flow_cache_;
  // For tracking flow-to-chain mapping
  std::unordered_map<std::string, std::set<Flow>> map_chain_to_flow_;

  FlowAction default_action_ = kDrop;

  // A slight delay of installing an OpenFlow rule for a flow.
  uint64_t now_;
  uint64_t rule_delay_ts_;

  std::string faas_service_addr_;
  std::string switch_service_addr_;
  std::string redis_service_ip_;

  // Our view of the server's exposed services.
  std::unique_ptr<bess::pb::FaaSControl::Stub> faas_stub_;
  // Our view of the swtich's exposed services.
  std::unique_ptr<bess::pb::SwitchControl::Stub> switch_stub_;
  // The reusable connection context to a redis server.
  redisContext* redis_ctx_;

  grpc::Status status_;

  // (Outdated) These are for FaaS controller's query.
  bess::pb::FlowInfo flow_request_;
  bess::pb::FlowTableEntry flow_response_;
  bess::pb::InsertFlowEntryRequest flowrule_request_;
  google::protobuf::Empty flowrule_response_;

  redisReply* redis_reply_;

  // (Outdated) LPM flow rules
  long unsigned int max_rules_count_;
  std::deque<FlowLpmRule> rules_;

  int active_flows_ = 0;

  // Local decision parameters
  bool local_decision_;
  bool mac_encoded_;
  uint egress_port_;
  std::string egress_mac_;

  mcslock lock_;
  std::mutex mu_;
};

#endif  // BESS_MODULES_FAAS_INGRESS_H_
