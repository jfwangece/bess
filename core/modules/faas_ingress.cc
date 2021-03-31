#include "faas_ingress.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/udp.h"
#include "../utils/tcp.h"

static const std::string kDefaultFaaSServicePort = "10515";
static const std::string kDefaultSwitchServicePort = "10516";
static const int kDefaultRedisServicePort = 6379;
static const int kDefaultFaaSIngressStoreSize = 1600;
static const uint64_t kDefaultRuleDelayMilliseconds = 0;


const Commands FaaSIngress::cmds = {
  {"add", "FaaSIngressArg", MODULE_CMD_FUNC(&FaaSIngress::CommandAdd),
   Command::THREAD_UNSAFE},
  {"clear", "EmptyArg", MODULE_CMD_FUNC(&FaaSIngress::CommandClear),
   Command::THREAD_SAFE},
  {"update", "FaaSIngressCommandUpdateArg",
   MODULE_CMD_FUNC(&FaaSIngress::CommandUpdate),
   Command::THREAD_SAFE}};

CommandResponse FaaSIngress::Init(const bess::pb::FaaSIngressArg &arg) {
  using bess::utils::Ethernet;
  using bess::utils::Ipv4;
  using bess::utils::Udp;
  using bess::utils::Tcp;

  if (arg.faas_service_ip().empty()) {
    LOG(INFO) << "No FaaS service IP provided. FaaSIngress forwards all packets";
    faas_service_addr_ = "";
  } else {
    if (arg.faas_service_port() > 0) {
      faas_service_addr_ = arg.faas_service_ip() + ":" + std::to_string(arg.faas_service_port());
    } else {
      faas_service_addr_ = arg.faas_service_ip() + ":" + kDefaultFaaSServicePort;
    }

    auto faas_channel = grpc::CreateChannel(faas_service_addr_, grpc::InsecureChannelCredentials());
    faas_stub_ = bess::pb::FaaSControl::NewStub(faas_channel);
  }

  if (arg.switch_service_ip().empty()) {
    LOG(INFO) << "No FaaS service IP provided. FaaSIngress forwards all packets";
    switch_service_addr_ = "";
  } else {
    if (arg.switch_service_port() > 0) {
      switch_service_addr_ = arg.switch_service_ip() + ":" + std::to_string(arg.switch_service_port());
    } else {
      switch_service_addr_ = arg.switch_service_ip() + ":" + kDefaultSwitchServicePort;
    }

    auto switch_channel = grpc::CreateChannel(switch_service_addr_, grpc::InsecureChannelCredentials());
    switch_stub_ = bess::pb::SwitchControl::NewStub(switch_channel);
  }

  redis_ctx_ = nullptr;
  if (arg.redis_service_ip().empty()) {
    LOG(INFO) << "No Redis service IP provided.";
    redis_service_ip_ = "";
  } else {
    redis_service_ip_ = arg.redis_service_ip();

    // Connecting
    redis_ctx_ = (redisContext*)redisConnect(redis_service_ip_.c_str(), kDefaultRedisServicePort);
    if (redis_ctx_ == nullptr) {
      LOG(INFO) << "Can't allocate redis context";
    } else if (redis_ctx_->err) {
      LOG(INFO) << "Connecting Error: " << redis_ctx_->errstr;
      redis_ctx_ = nullptr;
    } else {
      // Succeed.
      if (!arg.redis_password().empty()) {
        redis_reply_ = (redisReply*)redisCommand(redis_ctx_, "AUTH %s", arg.redis_password().c_str());
        if (redis_reply_->type == REDIS_REPLY_ERROR) {
            LOG(INFO) << "Failed to auth with Redis server";
            freeReplyObject(redis_reply_);
            redis_ctx_ = nullptr;
        }
      }
    }
  }

  if (arg.max_rules_count() > 0) {
    max_rules_count_ = arg.max_rules_count();
  } else {
    max_rules_count_ = kDefaultFaaSIngressStoreSize;
  }

  if (arg.rule_delay_ms() > 0) {
    rule_delay_ts_ = (uint64_t)arg.rule_delay_ms() * tsc_hz / 1000;
  } else {
    rule_delay_ts_ = kDefaultRuleDelayMilliseconds * tsc_hz / 1000;
  }

  for (const auto &rule : arg.rules()) {
    FlowRule new_rule = {
        .src_ip = Ipv4Prefix(rule.src_ip()),
        .dst_ip = Ipv4Prefix(rule.dst_ip()),
        .proto_ip = Ipv4::Proto::kTcp,
        .src_port = be16_t(static_cast<uint16_t>(rule.src_port())),
        .dst_port = be16_t(static_cast<uint16_t>(rule.dst_port())),
        .action = FlowAction(rule.action()),
        .egress_port = rule.egress_port(),
        .egress_mac = rule.egress_mac(),
        .encoded_mac = Ethernet::Address(),
        .active_ts = 0,
    };
    rules_.push_back(new_rule);
  }

  if (arg.flow_action() == "forward") {
    default_action_ = kForward;
  }

  local_decision_ = false;
  egress_port_ = 0;
  egress_mac_ = "00:00:00:00:00:01";
  if (arg.local_decision()) {
    local_decision_ = true;
  }

  return CommandSuccess();
}

CommandResponse FaaSIngress::CommandAdd(const bess::pb::FaaSIngressArg &arg) {
  Init(arg);
  return CommandSuccess();
}

CommandResponse FaaSIngress::CommandClear(const bess::pb::EmptyArg &) {
  Clear();
  return CommandSuccess();
}

CommandResponse FaaSIngress::CommandUpdate(const bess::pb::FaaSIngressCommandUpdateArg &arg) {
  mcslock_node_t mynode;
  mcs_lock(&lock_, &mynode);

  egress_port_ = arg.egress_port();
  egress_mac_ = arg.egress_mac();

  mcs_unlock(&lock_, &mynode);
  return CommandSuccess();
}

void FaaSIngress::Clear() {
  mcslock_node_t mynode;
  mcs_lock(&lock_, &mynode);
  rules_.clear();
  mcs_unlock(&lock_, &mynode);
}

void FaaSIngress::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  using bess::utils::Ethernet;
  using bess::utils::Ipv4;
  using bess::utils::Udp;
  using bess::utils::Tcp;

  if (faas_service_addr_.empty()) {
    RunNextModule(ctx, batch);
    return;
  }

  now_ = rdtsc();
  int cnt = batch->cnt();
  be16_t sport, dport;
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    size_t ip_bytes = ip->header_length << 2;
    if (ip->protocol == Ipv4::Proto::kTcp) {
      Tcp *tcp = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
      sport = tcp->src_port;
      dport = tcp->dst_port;
    } else if (ip->protocol == Ipv4::Proto::kUdp) {
      Udp *udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
      sport = udp->src_port;
      dport = udp->dst_port;
    } else {
      continue;
    }

    bool emitted = false;
    for (const auto &rule : rules_) {
      if (rule.Match(ip->src, ip->dst, ip->protocol, sport, dport)) { // An in-progress flow.
        emitted = true;
        if (now_ >= rule.active_ts) {
          eth->dst_addr = rule.encoded_mac;
          EmitPacket(ctx, pkt, 0);
        } else {
          if (rule.action == kForward) {
            eth->dst_addr = rule.encoded_mac;
            EmitPacket(ctx, pkt, 0);
          } else if (rule.action == kDrop) {
            DropPacket(ctx, pkt);
          }
        }
        break;  // Stop matching other rules
      }
    }

    if (!emitted) { // A new flow.
      FlowRule new_rule = {
        .src_ip = Ipv4Prefix(ToIpv4Address(ip->src) + "/32"),
        .dst_ip = Ipv4Prefix(ToIpv4Address(ip->dst) + "/32"),
        .proto_ip = ip->protocol,
        .src_port = be16_t(sport),
        .dst_port = be16_t(dport),
        .action = default_action_,
        .egress_port = 0,
        .egress_mac = "",
        .encoded_mac = Ethernet::Address(),
        .active_ts = 0,
      };

      if (local_decision_ && egress_port_ == 0) {
        // The controller decides to drop all new flows.
        DropPacket(ctx, pkt);
      } else if (!process_new_flow(new_rule)) {
        DropPacket(ctx, pkt);
      } else {
        // The rule is ready.. Emit the first packet of this flow!
        eth->dst_addr = new_rule.encoded_mac;
        EmitPacket(ctx, pkt, 0);
      }
    }
  }
}

bool FaaSIngress::process_new_flow(FlowRule &rule) {
  grpc::ClientContext ctx1, ctx2;

  if (local_decision_) {
    // use the local decision updated locally.
    mcslock_node_t mynode;
    mcs_lock(&lock_, &mynode);

    rule.set_action(egress_port_, egress_mac_);

    mcs_unlock(&lock_, &mynode);
  } else {
    // query the FaaS controller for a remote decison.
    flow_request_.set_ipv4_src(ToIpv4Address(rule.src_ip.addr));
    flow_request_.set_ipv4_dst(ToIpv4Address(rule.dst_ip.addr));
    flow_request_.set_ipv4_protocol(rule.proto_ip);
    flow_request_.set_tcp_sport(rule.src_port.value());
    flow_request_.set_tcp_dport(rule.dst_port.value());
    status_ = faas_stub_->UpdateFlow(&ctx1, flow_request_, &flow_response_);
    if (!status_.ok()) {
      return false;
    }

    rule.set_action(flow_response_.switch_port(), flow_response_.dmac());
    if (rule.dst_port.value() < 2000) {
      std::cout << flow_response_.switch_port();
      std::cout << rule.encoded_mac.ToString();
    }
  }

  if (!switch_service_addr_.empty()) {
    convert_rule_to_of_request(rule, flowrule_request_);
    status_ = switch_stub_->InsertFlowEntry(&ctx2, flowrule_request_, &flowrule_response_);
    if (!status_.ok()) {
      return false;
    }
  }

  bool rule_inserted = false;
  if (redis_ctx_ != nullptr) {
    std::string tmp_flow_msg = convert_rule_to_string(rule);

    for (int i = 0; i < 3; ++i) {
      redis_reply_ = (redisReply*)redisCommand(redis_ctx_, "PUBLISH %s %s", "faasctl", tmp_flow_msg.c_str());
      if (redis_reply_ == NULL) {
        continue;
      } else if (redis_reply_->type == REDIS_REPLY_ERROR) {
        freeReplyObject(redis_reply_);
      } else {
        rule_inserted = true;
        freeReplyObject(redis_reply_);
        break;
      }
    }
  }

  if (!rule_inserted) {
    LOG(ERROR) << "Failed to send a flow request";
    return false;
  }

  // Update the active timestamp for the new rule.
  now_ = rdtsc();
  rule.active_ts = now_ + rule_delay_ts_;

  rules_.emplace_front(rule);
  while (rules_.size() > max_rules_count_) {
    rules_.pop_back();
  }

  return true;
}

std::string FaaSIngress::convert_rule_to_string(FlowRule &rule) {
  return "assign," +
         ToIpv4Address(rule.src_ip.addr) + "," +
         ToIpv4Address(rule.dst_ip.addr) + "," +
         std::to_string(rule.proto_ip) + "," +
         std::to_string(rule.src_port.value()) + "," +
         std::to_string(rule.dst_port.value()) + "," +
         std::to_string(rule.egress_port) + "," +
         rule.egress_mac;
}

void FaaSIngress::convert_rule_to_of_request(FlowRule &rule, bess::pb::InsertFlowEntryRequest &req) {
  req.set_ipv4_src(ToIpv4Address(rule.src_ip.addr));
  req.set_ipv4_dst(ToIpv4Address(rule.dst_ip.addr));
  req.set_ipv4_protocol(rule.proto_ip);
  req.set_tcp_sport(rule.src_port.value());
  req.set_tcp_dport(rule.dst_port.value());
  req.set_switch_port(rule.egress_port);
  req.set_dmac(rule.egress_mac);
}

ADD_MODULE(FaaSIngress, "FaaSIngress",
          "FaaSIngress module that interacts with the switch controller to handle packet losses.")
