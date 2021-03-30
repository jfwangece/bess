#ifndef BESS_MODULES_FAASINGRESS_H_
#define BESS_MODULES_FAASINGRESS_H_

#include <grpc++/grpc++.h>
#include <hiredis/hiredis.h>
#include <deque>
#include <vector>
#include <string>

#include "pb/faas_msg.pb.h"
#include "pb/faas_msg.grpc.pb.h"
#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/mcslock.h"

using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Ethernet;
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
  bool Match(be32_t sip, be32_t dip, uint8_t pip, be16_t sport, be16_t dport) const {
    return src_ip.Match(sip) && dst_ip.Match(dip) &&
       (proto_ip == pip) &&
       (src_port == be16_t(0) || src_port == sport) &&
       (dst_port == be16_t(0) || dst_port == dport);
  }

  void set_action(uint o_port, const std::string& o_mac) {
    egress_port = o_port;
    egress_mac = o_mac;
    encoded_mac.FromString(o_mac);
    encoded_mac.bytes[0] = o_port & 0xff;
  }

  // Match
  Ipv4Prefix src_ip;
  Ipv4Prefix dst_ip;
  uint8_t proto_ip;
  be16_t src_port;
  be16_t dst_port;

  // Action for subsequent packets.
  FlowAction action;
  uint egress_port;
  std::string egress_mac;

  Ethernet::Address encoded_mac;
  uint64_t active_ts = 0;
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

  CommandResponse CommandAdd(const bess::pb::FaaSIngressArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);
  CommandResponse CommandUpdate(const bess::pb::FaaSIngressCommandUpdateArg &arg);

 private:
  bool process_new_flow(FlowRule &rule);
  void convert_rule_to_of_request(FlowRule &rule, bess::pb::InsertFlowEntryRequest &req);
  std::string convert_rule_to_string(FlowRule &rule);

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

  long unsigned int max_rules_count_;
  std::vector<FlowRule> rules_vector_;
  std::deque<FlowRule> rules_;

  // Local decision parameters
  bool local_decision_;
  uint egress_port_;
  std::string egress_mac_;

  mcslock lock_;
};

#endif  // BESS_MODULES_FAASINGRESS_H_
