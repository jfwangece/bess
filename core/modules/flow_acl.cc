#include "flow_acl.h"
#include "nfv_ctrl_msg.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"

namespace {
const uint64_t TIME_OUT_NS = 10ull * 1000 * 1000 * 1000; // 10 seconds
}

using bess::ctrl::FlowState;

const Commands FlowACL::cmds = {
    {"add", "FlowACLArg", MODULE_CMD_FUNC(&FlowACL::CommandAdd),
     Command::THREAD_UNSAFE},
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&FlowACL::CommandClear),
     Command::THREAD_UNSAFE}};

CommandResponse FlowACL::Init(const bess::pb::FlowACLArg &arg) {
  for (const auto &rule : arg.rules()) {
    ACLRule new_rule = {
        .src_ip = Ipv4Prefix(rule.src_ip()),
        .dst_ip = Ipv4Prefix(rule.dst_ip()),
        .src_port = be16_t(static_cast<uint16_t>(rule.src_port())),
        .dst_port = be16_t(static_cast<uint16_t>(rule.dst_port())),
        .drop = rule.drop()};
    rules_.push_back(new_rule);
  }

  // Read the metadata
  std::string attr_name = "flow_stats";
  using AccessMode = bess::metadata::Attribute::AccessMode;
  flow_stats_attr_id_ = AddMetadataAttr(attr_name, sizeof(FlowState*), AccessMode::kRead);

  return CommandSuccess();
}

CommandResponse FlowACL::CommandAdd(const bess::pb::FlowACLArg &arg) {
  Init(arg);
  return CommandSuccess();
}

CommandResponse FlowACL::CommandClear(const bess::pb::EmptyArg &) {
  rules_.clear();
  return CommandSuccess();
}

void FlowACL::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  using bess::utils::Ethernet;
  using bess::utils::Ipv4;
  using bess::utils::Tcp;

  gate_idx_t incoming_gate = ctx->current_igate;

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);

    if (ip->protocol != Ipv4::Proto::kTcp) {
      if (false) {
        EmitPacket(ctx, pkt, 0);
      }
      continue;
    }

    size_t ip_bytes = ip->header_length << 2;
    Tcp *tcp =
        reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);

    uint64_t now = ctx->current_ns;
    bool emitted = false;

    if (bess::ctrl::exp_id <= 1) { // Ironside      
      FlowState *state = *(_ptr_attr_with_offset<FlowState*>(this->attr_offset(flow_stats_attr_id_), pkt));

      if (state->acl.pkt_cnt_ == 0) {
        state->acl.pkt_cnt_ = 1;
        for (const auto &rule : rules_) {
          if (rule.Match(ip->src, ip->dst, tcp->src_port, tcp->dst_port)) {
            if (!rule.drop) {
              state->acl.SetACLPass();
              emitted = true;
            }
            break;  // Stop matching other rules
          }
        }
      } else {
        if (state->acl.IsACLPass()) {
          emitted = true;
        }
      }

      state->acl.SetExpiryTime(now + TIME_OUT_NS);
    }
    else { // Metron, Dyssect
      Flow flow;
      flow.src_ip = ip->src;
      flow.dst_ip = ip->dst;
      flow.src_port = tcp->src_port;
      flow.dst_port = tcp->dst_port;

      // Find existing flow, if we have one.
      std::unordered_map<Flow, FlowRecord, FlowHash>::iterator it =
          flow_cache_.find(flow);

      if (it != flow_cache_.end()) {
        if (now >= it->second.ExpiryTime()) { // an outdated flow
          flow_cache_.erase(it);
          active_flows_ -= 1;
          it = flow_cache_.end();
        } else { // an existing flow
          if (it->second.IsACLPass()) {
            emitted = true;
          }
        }
      }

      if (it == flow_cache_.end()) {
        std::tie(it, std::ignore) = flow_cache_.emplace(
            std::piecewise_construct, std::make_tuple(flow), std::make_tuple());

        for (const auto &rule : rules_) {
          if (rule.Match(ip->src, ip->dst, tcp->src_port, tcp->dst_port)) {
            if (!rule.drop) {
              it->second.SetACLPass();
              emitted = true;
            }
            break;  // Stop matching other rules
          }
        }
        active_flows_ += 1;
      }

      it->second.SetExpiryTime(now + TIME_OUT_NS);

      if (tcp->flags & Tcp::Flag::kFin) {
        flow_cache_.erase(it);
        active_flows_ -= 1;
      }
    }

    // Determine whether to drop or forward |pkt|.
    if (false) {
      if (!emitted) {
        DropPacket(ctx, pkt);
      } else {
        EmitPacket(ctx, pkt, incoming_gate);
      }
    }
  }

  RunNextModule(ctx, batch);
}

ADD_MODULE(FlowACL, "flow_acl", "ACL module with a per-flow hash table")
