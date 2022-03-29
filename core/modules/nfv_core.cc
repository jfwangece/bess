#include "nfv_core.h"

#include <fstream>

#include "../port.h"
#include "../drivers/pmd.h"
#include "../utils/ether.h"
#include "../utils/format.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/udp.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;
using bess::utils::Udp;

namespace {
} /// namespace

const Commands NFVCore::cmds = {
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&NFVCore::CommandClear),
     Command::THREAD_UNSAFE},
    {"set_burst", "NFVCoreCommandSetBurstArg", MODULE_CMD_FUNC(&NFVCore::CommandSetBurst),
     Command::THREAD_SAFE},
};

int NFVCore::Resize(int slots) {
  struct llring *old_queue = queue_;
  struct llring *new_queue;

  int bytes = llring_bytes_with_slots(slots);

  new_queue =
      reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));
  if (!new_queue) {
    return -ENOMEM;
  }

  int ret = llring_init(new_queue, slots, 0, 1);
  if (ret) {
    std::free(new_queue);
    return -EINVAL;
  }

  /* migrate packets from the old queue */
  if (old_queue) {
    bess::Packet *pkt;

    while (llring_sc_dequeue(old_queue, (void **)&pkt) == 0) {
      ret = llring_sp_enqueue(new_queue, pkt);
      if (ret == -LLRING_ERR_NOBUF) {
        bess::Packet::Free(pkt);
      }
    }

    std::free(old_queue);
  }

  queue_ = new_queue;
  size_ = slots;

  return 0;
}

CommandResponse NFVCore::Init([[maybe_unused]]const bess::pb::NFVCoreArg &arg) {
  const char *port_name;
  task_id_t tid;
  burst_ = bess::PacketBatch::kMaxBurst;

  if (!arg.port().empty()) {
    port_name = arg.port().c_str();
    qid_ = arg.qid();
    const auto &it = PortBuilder::all_ports().find(port_name);
    if (it == PortBuilder::all_ports().end()) {
      return CommandFailure(ENODEV, "Port %s not found", port_name);
    }
    port_ = it->second;

    tid = RegisterTask((void *)(uintptr_t)qid_);
    if (tid == INVALID_TASK_ID) {
      return CommandFailure(ENOMEM, "Task creation failed");
    }

    Resize(2048);
  }

  core_id_ = 0;
  if (arg.core_id() > 0) {
    core_id_ = arg.core_id();
  }
  core_.core_id = core_id_;

  // Init
  epoch_flow_thresh_ = 35;
  epoch_packet_thresh_ = 80;
  epoch_packet_arrival_ = 0;
  epoch_packet_processed_ = 0;
  epoch_packet_queued_ = 0;
  epoch_flow_cache_.clear();
  per_flow_packet_counter_.clear();
  return CommandSuccess();
}

void NFVCore::DeInit() {
  bess::Packet *pkt;

  if (queue_) {
    while (llring_sc_dequeue(queue_, (void **)&pkt) == 0) {
      bess::Packet::Free(pkt);
    }
    std::free(queue_);
  }
}

CommandResponse NFVCore::CommandClear(const bess::pb::EmptyArg &) {
  per_flow_packet_counter_.clear();
  return CommandSuccess();
}

CommandResponse NFVCore::CommandSetBurst(
    const bess::pb::NFVCoreCommandSetBurstArg &arg) {
  if (arg.burst() > bess::PacketBatch::kMaxBurst) {
    return CommandFailure(EINVAL, "burst size must be [0,%zu]",
                          bess::PacketBatch::kMaxBurst);
  } else {
    burst_ = arg.burst();
    return CommandSuccess();
  }
}

std::string NFVCore::GetDesc() const {
  return bess::utils::Format("%s:%hhu/%d", port_->name().c_str(), qid_, llring_count(queue_));
}

/* to downstream */
struct task_result NFVCore::RunTask(Context *ctx, bess::PacketBatch *batch,
                                     void *arg) {
  using bess::utils::all_local_core_stats;

  Port *p = port_;

  const queue_t qid = (queue_t)(uintptr_t)arg;
  const int burst = ACCESS_ONCE(burst_);

  // We don't use ctx->current_ns here for better accuracy
  curr_ts_ns_ = tsc_to_ns(rdtsc());

  update_traffic_stats();

  while (1) {
    // Should check llring_free_count(queue_)
    batch->set_cnt(p->RecvPackets(qid, batch->pkts(), 32));
    if (batch->cnt()) {
      // To update |epoch_packet_arrival_| and |epoch_flow_cache_|
      UpdateEpochStats(batch);
      // Note: need to consider possible drops due to |queue_| overflow
      llring_sp_enqueue_burst(queue_, (void **)batch->pkts(), batch->cnt());
    }
    if (batch->cnt() < 30) {
      break;
    }
  }

  // Process one batch
  uint32_t cnt = llring_sc_dequeue_burst(queue_, (void **)batch->pkts(), burst);
  if (cnt == 0) {
    return {.block = false, .packets = 0, .bits = 0};
  }
  batch->set_cnt(cnt);

  epoch_packet_processed_ += cnt;
  epoch_packet_queued_ = llring_count(queue_);

  uint64_t total_bytes = 0;
  for (uint32_t i = 0; i < cnt; i++) {
    total_bytes += batch->pkts()[i]->total_len();
  }

  // Update for NFVMonitor (the current epoch info)
  all_local_core_stats[core_id_]->active_flow_count = epoch_flow_cache_.size();
  all_local_core_stats[core_id_]->packet_rate = epoch_packet_arrival_;
  all_local_core_stats[core_id_]->packet_processed = epoch_packet_processed_;
  all_local_core_stats[core_id_]->packet_queued = epoch_packet_queued_;

  // ProcessBatch(ctx, batch);
  RunNextModule(ctx, batch);

  return {.block = false,
          .packets = cnt,
          .bits = (total_bytes + cnt * 24) * 8};
}

void NFVCore::UpdateEpochStats(bess::PacketBatch *batch) {
  Flow flow;
  Tcp *tcp = nullptr;
  Udp *udp = nullptr;

  int cnt = batch->cnt();
  epoch_packet_arrival_ += cnt;

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

    // Find existing flow, if we have one.
    auto it = epoch_flow_cache_.find(flow);
    if (it == epoch_flow_cache_.end()) {
      epoch_flow_cache_.emplace(flow, true);
    }
  }
}

/* from upstream */
void NFVCore::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
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

    if (epoch_packet_arrival_ > epoch_packet_thresh_) {
      DropPacket(ctx, pkt);
      continue;
    }
    // Update RSS bucket packet counters.
    uint32_t id = bess::utils::bucket_stats.rss_hash_to_id(reinterpret_cast<rte_mbuf*>(pkt)->hash.rss);
    bess::utils::bucket_stats.bucket_table_lock.lock_shared();
    /*
     * Access within the same core is synchronized by packet_counter_lock.
     * We don't need to synchronize between cores as they are expected to
     * access differnt indexes.
     */
    bess::utils::bucket_stats.per_bucket_packet_counter[id] += 1;
    bess::utils::bucket_stats.bucket_table_lock.unlock_shared();

    epoch_packet_arrival_ += 1;
    EmitPacket(ctx, pkt);
  }
}

bool NFVCore::update_traffic_stats() {
  using bess::utils::all_core_stats_chan;

  bool is_new_epoch = (all_core_stats_chan[core_id_]->Size() > 0);

  if (is_new_epoch) {
    // At the end of one epoch, NFVCore requests software queues to
    // absorb the existing packet queue in the coming epoch.
//    RequestNSwQ(core_id_, 4);


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

    epoch_flow_cache_.clear();
    epoch_packet_arrival_ = 0;
    epoch_packet_processed_ = 0;
  }

  return true;
}

ADD_MODULE(NFVCore, "nfv_core", "It handles traffic burstiness at each core")
