#include "nfv_core.h"

#include <fstream>

#include "../port.h"
#include "../drivers/pmd.h"
#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/udp.h"

namespace {
} /// namespace

const Commands NFVCore::cmds = {
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&NFVCore::CommandClear),
     Command::THREAD_UNSAFE},
};

CommandResponse NFVCore::Init([[maybe_unused]]const bess::pb::NFVCoreArg &arg) {
  core_id_ = 0;
  if (arg.core_id() > 0) {
    core_id_ = arg.core_id();
  }
  core_.core_id = core_id_;

  // Init
  epoch_flow_thresh_ = 35;
  epoch_packet_thresh_ = 80;
  epoch_packet_counter_ = 0;
  epoch_flow_cache_.clear();
  per_flow_packet_counter_.clear();
  return CommandSuccess();
}

CommandResponse NFVCore::CommandClear(const bess::pb::EmptyArg &) {
  per_flow_packet_counter_.clear();
  return CommandSuccess();
}

void NFVCore::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  using bess::utils::Ethernet;
  using bess::utils::Ipv4;
  using bess::utils::Tcp;
  using bess::utils::Udp;

  Flow flow;
  Tcp *tcp = nullptr;
  Udp *udp = nullptr;

  // We don't use ctx->current_ns here for better accuracy
  curr_ts_ns_ = tsc_to_ns(rdtsc());

  update_traffic_stats();

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    size_t ip_bytes = ip->header_length << 2;

    if (ip->protocol == Ipv4::Proto::kTcp) {
      tcp = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
      flow.src_ip = ip->src;
      flow.dst_ip = ip->dst;
      flow.src_port = tcp->src_port;
      flow.dst_port = tcp->dst_port;
      flow.proto_ip = ip->protocol;
    } else if (ip->protocol == Ipv4::Proto::kUdp) {
      udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
      flow.src_ip = ip->src;
      flow.dst_ip = ip->dst;
      flow.src_port = udp->src_port;
      flow.dst_port = udp->dst_port;
      flow.proto_ip = ip->protocol;
    } else {
      continue;
    }

    // Drop bursty flows
    if (per_flow_packet_counter_.find(flow) != per_flow_packet_counter_.end()) {
      DropPacket(ctx, pkt);
      continue;
    }

    // Find existing flow, if we have one.
    auto epoch_flow_it = epoch_flow_cache_.find(flow);
    if (epoch_flow_it == epoch_flow_cache_.end()) {
      if (epoch_flow_cache_.size() > epoch_flow_thresh_) {
        DropPacket(ctx, pkt);
        continue;
      }
      epoch_flow_cache_.emplace(flow, true);
    }

    if (epoch_packet_counter_ > epoch_packet_thresh_) {
      DropPacket(ctx, pkt);
      continue;
    }

    epoch_packet_counter_ += 1;
    EmitPacket(ctx, pkt);
  }
}

bool NFVCore::update_traffic_stats() {
  using bess::utils::all_core_stats_chan;

  bool is_new_epoch = (all_core_stats_chan[core_id_]->Size() > 0);
  if (is_new_epoch) {
    epoch_flow_cache_.clear();
    epoch_packet_counter_ = 0;
  }

  CoreStats* stats_ptr = nullptr;
  while (all_core_stats_chan[core_id_]->Size()) {
    all_core_stats_chan[core_id_]->Pop(stats_ptr);
    core_.packet_rate = stats_ptr->packet_rate;
    core_.p99_latency = stats_ptr->p99_latency;
    for (auto &f : stats_ptr->bursty_flows) {
      per_flow_packet_counter_.emplace(f, 1);
    }
    delete (stats_ptr);
    stats_ptr = nullptr;

    epoch_flow_thresh_ = 35;
    epoch_packet_thresh_ = 80;
  }

  return true;
}

ADD_MODULE(NFVCore, "nfv_core", "It handles traffic burstiness at each core")
