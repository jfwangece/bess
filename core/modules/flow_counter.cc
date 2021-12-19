#include "flow_counter.h"

#include <unistd.h>

#include "../utils/endian.h"
#include "../utils/ether.h"
#include "../utils/format.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/udp.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;

namespace {
const uint64_t TIME_OUT_NS = 10ull * 1000 * 1000 * 1000; // 10 seconds
}

const Commands FlowCounter::cmds = {
  {"clear", "EmptyArg", MODULE_CMD_FUNC(&FlowCounter::CommandClear),
   Command::THREAD_SAFE},
  {"get_summary", "EmptyArg",
   MODULE_CMD_FUNC(&FlowCounter::CommandGetSummary), Command::THREAD_SAFE},
};

CommandResponse FlowCounter::Init(const bess::pb::FlowCounterArg &) {
  flow_cache_.clear();
  is_active_ = true;
  mcs_lock_init(&lock_);

  return CommandSuccess();
}

void FlowCounter::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  if (!is_active_) {
    RunNextModule(ctx, batch);
    return;
  }

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);

    if (ip->protocol != Ipv4::Proto::kTcp) {
      EmitPacket(ctx, pkt, 0);
      continue;
    }

    size_t ip_bytes = ip->header_length << 2;
    Tcp *tcp =
        reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);

    Flow flow;
    flow.src_ip = ip->src;
    flow.dst_ip = ip->dst;
    flow.src_port = tcp->src_port;
    flow.dst_port = tcp->dst_port;

    uint64_t now = ctx->current_ns;

    // Find existing flow, if we have one.
    std::unordered_map<Flow, FlowRecord, FlowHash>::iterator it =
        flow_cache_.find(flow);

    if (it != flow_cache_.end()) {
      if (now >= it->second.ExpiryTime()) { // an outdated flow
        flow_cache_.erase(it);
        active_flows_ -= 1;
        it = flow_cache_.end();
      }
    }

    if (it == flow_cache_.end()) {
      std::tie(it, std::ignore) = flow_cache_.emplace(
          std::piecewise_construct, std::make_tuple(flow), std::make_tuple());
      active_flows_ += 1;
    }

    it->second.pkt_cnt_ += 1;
    it->second.SetExpiryTime(now + TIME_OUT_NS);

    if (tcp->flags & Tcp::Flag::kFin) {
      flow_cache_.erase(it);
      active_flows_ -= 1;
    }
  }

  RunNextModule(ctx, batch);
}

void FlowCounter::Reset() {
  Clear();
  Start();
}

void FlowCounter::Clear() {
  mcslock_node_t mynode;
  mcs_lock(&lock_, &mynode);

  is_active_ = false;
  usleep(500000); // Sleep for 500 milliseconds.
  flow_cache_.clear();

  mcs_unlock(&lock_, &mynode);
}

void FlowCounter::Start() {
  mcslock_node_t mynode;
  mcs_lock(&lock_, &mynode);
  is_active_ = true;
  mcs_unlock(&lock_, &mynode);
}

void FlowCounter::Stop() {
  mcslock_node_t mynode;
  mcs_lock(&lock_, &mynode);
  is_active_ = false;
  mcs_unlock(&lock_, &mynode);
}

CommandResponse FlowCounter::CommandReset(const bess::pb::EmptyArg &) {
  Reset();
  return CommandResponse();
}

CommandResponse FlowCounter::CommandClear(const bess::pb::EmptyArg &) {
  Clear();
  return CommandResponse();
}

CommandResponse FlowCounter::CommandStart(const bess::pb::EmptyArg &) {
  Start();
  return CommandResponse();
}

CommandResponse FlowCounter::CommandStop(const bess::pb::EmptyArg &) {
  Stop();
  return CommandResponse();
}

CommandResponse FlowCounter::CommandGetSummary(const bess::pb::EmptyArg &) {
  Stop();
  bess::pb::DistributedFlowCounterGetSummaryRespondArg r;
  r.set_flow_count(flow_cache_.size());
  Start();
  return CommandSuccess(r);
}

std::string FlowCounter::GetDesc() const {
  return bess::utils::Format("%d flows", active_flows_);
}

ADD_MODULE(FlowCounter, "flow_counter",
          "Counts the number of flows observed by this instance")
