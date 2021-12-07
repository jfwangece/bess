#include "flow_counter.h"

#include <unistd.h>

#include "../utils/endian.h"
#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/udp.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;
using bess::utils::Udp;
using bess::utils::be32_t;

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

  // uint64_t now = rdtsc();
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

    auto curr_flow = std::make_tuple(ip->src, ip->dst, ip->protocol, sport, dport);
    bool found = flow_cache_.find(curr_flow) != flow_cache_.end();
    if (found) { // No need to update.
      continue;
    } else {
      flow_cache_.insert(curr_flow);
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

ADD_MODULE(FlowCounter, "flow_counter",
          "Counts the number of flows observed by this instance")
