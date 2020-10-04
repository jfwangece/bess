#include "faas_ingress.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/udp.h"
#include "../utils/tcp.h"

static const std::string kDefaultFaaSServicePort = "10515";
static const std::string kDefaultSwitchServicePort = "10516";
static const int kDefaultRedisServicePort = 6379;

const Commands FaaSIngress::cmds = {
  {"add", "FaaSIngressArg", MODULE_CMD_FUNC(&FaaSIngress::CommandAdd),
   Command::THREAD_UNSAFE},
  {"clear", "EmptyArg", MODULE_CMD_FUNC(&FaaSIngress::CommandClear),
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
    };
    rules_.push_back(new_rule);
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

  //gate_idx_t incoming_gate = ctx->current_igate;
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
        if (rule.action == kForward) {
          emitted = true;
          EmitPacket(ctx, pkt, 0);
        }
        break;  // Stop matching other rules
      }
    }

    if (!emitted) {
      FlowRule new_rule = {
        .src_ip = Ipv4Prefix(ToIpv4Address(ip->src) + "/32"),
        .dst_ip = Ipv4Prefix(ToIpv4Address(ip->dst) + "/32"),
        .proto_ip = ip->protocol,
        .src_port = be16_t(sport),
        .dst_port = be16_t(dport),
        .action = FlowAction(2),
        .egress_port = 0,
        .egress_mac = "",
      };

      if (!process_new_flow(new_rule)) {
        DropPacket(ctx, pkt);
      }
    }
  }
}

bool FaaSIngress::process_new_flow(FlowRule &rule) {
  grpc::ClientContext ctx1, ctx2;

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

  if (!switch_service_addr_.empty()) {
    convert_rule_to_of_request(rule, flowrule_request_);
    status_ = switch_stub_->InsertFlowEntry(&ctx2, flowrule_request_, &flowrule_response_);
    if (!status_.ok()) {
      return false;
    }
  }

  if (redis_ctx_ != nullptr) {
    std::string tmp_flow_msg = convert_rule_to_string(rule);
    redis_reply_ = (redisReply*)redisCommand(redis_ctx_, "PUBLISH %s %s", "flow", tmp_flow_msg.c_str());
    if (redis_reply_ == NULL) {
      LOG(INFO) << "Failed to send a flow request";
      return false;
    } else if (redis_reply_->type == REDIS_REPLY_ERROR) {
      LOG(INFO) << "Failed to send a flow";
      freeReplyObject(redis_reply_);
      return false;
    }

    //LOG(INFO) << tmp_flow_msg;
    freeReplyObject(redis_reply_);
  }

  rules_.push_back(rule);
  return true;
}

std::string FaaSIngress::convert_rule_to_string(FlowRule &rule) {
  return ToIpv4Address(rule.src_ip.addr) + "," +
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
