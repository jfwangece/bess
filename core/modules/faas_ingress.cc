#include "faas_ingress.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/udp.h"
#include "../utils/tcp.h"

const Commands FaaSIngress::cmds = {
  {"add", "FaaSIngressArg", MODULE_CMD_FUNC(&FaaSIngress::CommandAdd),
   Command::THREAD_UNSAFE},
  {"clear", "EmptyArg", MODULE_CMD_FUNC(&FaaSIngress::CommandClear),
   Command::THREAD_SAFE}};

CommandResponse FaaSIngress::Init(const bess::pb::FaaSIngressArg &arg) {
  for (const auto &rule : arg.rules()) {
    FlowRule new_rule = {
        .src_ip = Ipv4Prefix(rule.src_ip()),
        .dst_ip = Ipv4Prefix(rule.dst_ip()),
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

  gate_idx_t incoming_gate = ctx->current_igate;

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
      if (rule.Match(ip->src, ip->dst, sport, dport)) { // An in-progress flow.
        if (rule.action == kForward) {
          emitted = true;
          EmitPacket(ctx, pkt, incoming_gate);
        }
        break;  // Stop matching other rules
      }
    }

    process_new_flow();

    if (!emitted) {
      DropPacket(ctx, pkt);
    }
  }
}

void FaaSIngress::process_new_flow() {
  return;
}

ADD_MODULE(FaaSIngress, "FaaSIngress", "FaaSIngress module")
