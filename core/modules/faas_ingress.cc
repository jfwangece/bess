#include "faas_ingress.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/udp.h"
#include "../utils/tcp.h"

namespace {
const uint64_t TIME_OUT_NS = 10ull * 1000 * 1000 * 1000; // 10 seconds

const std::string kDefaultFaaSServicePort = "10515";
const std::string kDefaultSwitchServicePort = "10516";
const int kDefaultRedisServicePort = 6379;
const int kDefaultFaaSIngressStoreSize = 1600;
const uint64_t kDefaultRuleDelayMilliseconds = 0;
}

const Commands FaaSIngress::cmds = {
  {"add", "FaaSIngressArg", MODULE_CMD_FUNC(&FaaSIngress::CommandAdd),
   Command::THREAD_UNSAFE},
  {"clear", "EmptyArg", MODULE_CMD_FUNC(&FaaSIngress::CommandClear),
   Command::THREAD_SAFE},
  {"update", "FaaSIngressCommandUpdateArg",
   MODULE_CMD_FUNC(&FaaSIngress::CommandUpdate),
   Command::THREAD_SAFE},
  {"migrate", "FaaSIngressCommandMigrateArg",
   MODULE_CMD_FUNC(&FaaSIngress::CommandMigrate),
   Command::THREAD_SAFE},
};

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
    FlowLpmRule new_rule = {
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

  // For a multi-server sertting, this module encodes both egress
  // port and MAC addr in the packet's destination egress MAC addr.
  // Note: the first 2-byte field is replaced with the switch port #.
  mac_encoded_ = true;
  if (!arg.mac_encoded()) {
    mac_encoded_ = false;
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
  const std::lock_guard<std::mutex> lock(mu_);

  egress_port_ = arg.egress_port();
  egress_mac_ = arg.egress_mac();
  map_chain_to_flow_.emplace(egress_mac_, std::deque<Flow>());
  return CommandSuccess();
}

CommandResponse FaaSIngress::CommandMigrate(const bess::pb::FaaSIngressCommandMigrateArg &arg) {
  const std::lock_guard<std::mutex> lock(mu_);

  std::string from = arg.from_sg();
  std::string to = arg.to_sg();
  auto from_it = map_chain_to_flow_.find(from);
  auto to_it = map_chain_to_flow_.find(to);
  if (from_it == map_chain_to_flow_.end() || to_it == map_chain_to_flow_.end()) {
    return CommandSuccess();
  }

  // |from_it->second| is a std::deque
  double sum_rate = 0.0;
  while (from_it->second.size() > 0 && sum_rate < arg.rate_diff()) {
    auto head = from_it->second.front();
    auto flow_it = flow_cache_.find(head);
    if (flow_it == flow_cache_.end()) { continue; }

    from_it->second.pop_front();
    to_it->second.emplace_front(head);
    sum_rate += flow_it->second.pkt_rate_;
    flow_it->second.set_action(mac_encoded_, egress_port_, to);
  }
  return CommandSuccess();
}

void FaaSIngress::Clear() {
  const std::lock_guard<std::mutex> lock(mu_);

  rules_.clear();
  active_flows_ = 0;

  // Clear remote if necessary.
  if (redis_ctx_ != nullptr) {
    bool is_successful = false;
    std::string reset_switch_str = "reset,all";
    for (int i = 0; i < 3; ++i) {
      redis_reply_ = (redisReply*)redisCommand(redis_ctx_, "PUBLISH %s %s", "faasctl", reset_switch_str.c_str());
      if (redis_reply_ == NULL) {
        continue;
      } else if (redis_reply_->type == REDIS_REPLY_ERROR) {
        freeReplyObject(redis_reply_);
      } else {
        is_successful = true;
        freeReplyObject(redis_reply_);
        break;
      }
    }
    if (!is_successful) {
      LOG(ERROR) << "Failed to reset the OpenFlow switch";
    }
  }
}

void FaaSIngress::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  using bess::utils::Ethernet;
  using bess::utils::Ipv4;
  using bess::utils::Udp;
  using bess::utils::Tcp;

  if (!local_decision_ && faas_service_addr_.empty()) {
    RunNextModule(ctx, batch);
    return;
  }

  now_ = rdtsc();
  uint64_t now = ctx->current_ns;
  int cnt = batch->cnt();
  be16_t sport, dport;
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    size_t ip_bytes = ip->header_length << 2;
    Tcp *tcp = nullptr;
    Udp *udp = nullptr;
    if (ip->protocol == Ipv4::Proto::kTcp) {
      tcp = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
      sport = tcp->src_port;
      dport = tcp->dst_port;
    } else if (ip->protocol == Ipv4::Proto::kUdp) {
      udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
      sport = udp->src_port;
      dport = udp->dst_port;
    } else {
      DropPacket(ctx, pkt);
      continue;
    }

    // Maintain per-flow counters
    Flow flow;
    flow.src_ip = ip->src;
    flow.dst_ip = ip->dst;
    flow.src_port = sport;
    flow.dst_port = dport;

    // Find existing flow, if we have one.
    std::unordered_map<Flow, FlowRoutingRule, FlowHash>::iterator it =
        flow_cache_.find(flow);

    bool emitted = false;
    if (it != flow_cache_.end()) {
      if (now >= it->second.ExpiryTime()) { // an outdated flow
        flow_cache_.erase(it);
        active_flows_ -= 1;
        it = flow_cache_.end();
      } else { // an existing flow
        emitted = true;
        eth->dst_addr = it->second.encoded_mac_;
      }
    }

    if (it == flow_cache_.end()) {
      FlowRoutingRule new_rule("02:42:01:c2:02:fe");

      if (local_decision_ && egress_port_ == 0) {
        // The controller decides to drop all new flows.
        emitted = false;
      } else if (!process_new_flow(flow, new_rule)) {
        emitted = false;
      } else {
        std::tie(it, std::ignore) = flow_cache_.emplace(
            std::piecewise_construct,
            std::make_tuple(flow), std::make_tuple(new_rule));
        active_flows_ += 1;

        eth->dst_addr = it->second.encoded_mac_;
        it->second.packet_count_ += 1;
        it->second.SetExpiryTime(now + TIME_OUT_NS);
        it->second.UpdateRate(now);
        emitted = true;
      }
    }

    // To send or to drop ..
    if (!emitted) {
      DropPacket(ctx, pkt);
    } else {
      EmitPacket(ctx, pkt, 0);
    }

    if (tcp != nullptr && tcp->flags & Tcp::Flag::kFin) {
      flow_cache_.erase(it);
      active_flows_ -= 1;
    }

    /*
    // (Outdated) LPM flow rules
    for (const auto &rule : rules_) {
      if (rule.Match(ip->src, ip->dst, ip->protocol, sport, dport)) {
        emitted = true;

        if (now_ > rule.active_ts) {
          // Case 1: the new rule is active now at the ToR switch
          // We still forward this packet because a FlowMod operation
          // may make the flow rule invalid at the switch.
          eth->dst_addr = rule.encoded_mac;
          EmitPacket(ctx, pkt, 0);
          //DropPacket(ctx, pkt);
        } else {
          // Case 2: the new rule has not been installed
          // By default, the ingress applies the rule and forwards the packet
          if (rule.action == kForward) {
            eth->dst_addr = rule.encoded_mac;
            EmitPacket(ctx, pkt, 0);
          } else if (rule.action == kDrop) {
            DropPacket(ctx, pkt);
          }
        }

        auto it = map_flow_to_counter_.find(flow);
        if (it != map_flow_to_counter_.end()) {
          it->second.temp_pkt_cnt += 1;
        }

        break;  // Stop matching other rules
      }
    }

    if (!emitted) { // A new flow: no matched rule.
      FlowLpmRule new_rule = {
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
      } else if (!process_new_flow(flow, new_rule)) {
        DropPacket(ctx, pkt);
      } else {
        // The rule is ready.. Emit the first packet of this flow!
        eth->dst_addr = new_rule.encoded_mac;
        EmitPacket(ctx, pkt, 0);
      }
    }
    */
  }
}

bool FaaSIngress::process_new_flow(Flow &flow, FlowRoutingRule &rule) {
  grpc::ClientContext ctx1, ctx2;

  if (local_decision_) {
    // use the local decision updated locally.
    mu_.lock();
    rule.set_action(mac_encoded_, egress_port_, egress_mac_);
    map_chain_to_flow_[egress_mac_].emplace_front(flow);
    mu_.unlock();
  } else {
    // query the FaaS controller for a remote decison.
    flow_request_.set_ipv4_src(ToIpv4Address(flow.src_ip));
    flow_request_.set_ipv4_dst(ToIpv4Address(flow.dst_ip));
    flow_request_.set_ipv4_protocol(flow.proto_ip);
    flow_request_.set_tcp_sport(flow.src_port.value());
    flow_request_.set_tcp_dport(flow.dst_port.value());
    status_ = faas_stub_->UpdateFlow(&ctx1, flow_request_, &flow_response_);
    if (!status_.ok()) {
      return false;
    }

    rule.set_action(mac_encoded_, flow_response_.switch_port(), flow_response_.dmac());
  }

  // Update the switch flow table only if the switch Redis channel is ready
  if (redis_ctx_ != nullptr) {
    bool rule_inserted = false;
    std::string tmp_flow_msg = convert_rule_to_string(flow, rule);

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

    // Print an error message after 3 trials
    if (!rule_inserted) {
      LOG(ERROR) << "Failed to send a flow request";
      return false;
    }
  }

  // Update the active timestamp for the new rule.
  // now_ = rdtsc();
  // rule.active_ts = now_ + rule_delay_ts_;

  // rules_.emplace_front(rule);
  // while (rules_.size() > max_rules_count_) {
  //   rules_.pop_back();
  // }

  return true;
}

std::string FaaSIngress::convert_rule_to_string(Flow &flow, FlowRoutingRule &rule) {
  return "assign," +
         ToIpv4Address(flow.src_ip) + "," +
         ToIpv4Address(flow.dst_ip) + "," +
         std::to_string(flow.proto_ip) + "," +
         std::to_string(flow.src_port.value()) + "," +
         std::to_string(flow.dst_port.value()) + "," +
         std::to_string(rule.egress_port_) + "," +
         rule.egress_mac_;
}

ADD_MODULE(FaaSIngress, "FaaSIngress",
          "FaaSIngress module that interacts with the switch controller to handle packet losses.")
