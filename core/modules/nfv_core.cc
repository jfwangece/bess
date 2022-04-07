#include "nfv_core.h"

#include <bitset>
#include <fstream>

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

bool ParseFlowFromPacket(Flow *flow, bess::Packet *pkt) {
  Ethernet *eth = pkt->head_data<Ethernet *>();
  Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
  size_t ip_bytes = ip->header_length << 2;

  if (ip->protocol == Ipv4::Proto::kTcp) {
    Tcp *tcp = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
    flow->src_ip = ip->src;
    flow->dst_ip = ip->dst;
    flow->src_port = tcp->src_port;
    flow->dst_port = tcp->dst_port;
    flow->proto_ip = ip->protocol;
  } else if (ip->protocol == Ipv4::Proto::kUdp) {
    Udp *udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
    flow->src_ip = ip->src;
    flow->dst_ip = ip->dst;
    flow->src_port = udp->src_port;
    flow->dst_port = udp->dst_port;
    flow->proto_ip = ip->protocol;
  } else {
    return false;
  }
  return true;
}

// NFVCore member functions
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

CommandResponse NFVCore::Init(const bess::pb::NFVCoreArg &arg) {
  const char *port_name;
  task_id_t tid;
  burst_ = bess::PacketBatch::kMaxBurst;

  // Configure the target NIC queue
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

  // Configure the target CPU core ID
  core_id_ = 0;
  if (arg.core_id() > 0) {
    core_id_ = arg.core_id();
  }
  core_.core_id = core_id_;

  // Add a metadata filed for recording flow stats pointer
  std::string attr_name = "flow_stats";
  using AccessMode = bess::metadata::Attribute::AccessMode;
  flow_stats_attr_id_ = AddMetadataAttr(attr_name, sizeof(uint64_t), AccessMode::kWrite);

  // Init
  nfv_cores[core_id_] = this;

  // Begin with 0 software queue
  sw_q_mask_ = NFVCtrlRequestNSwQ(core_id_, 4);
  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    uint64_t sw_q_idx = (1ULL << i) & sw_q_mask_;
    if (sw_q_idx != 0) {
      auto &it = sw_q_.emplace_back (i);
      it.sw_q = sw_q[i];
    }
  }
  LOG(INFO) << "Core " << core_id_ << " has " << sw_q_.size() << " sw_q. q_mask: " << std::bitset<64> (sw_q_mask_);

  epoch_flow_thresh_ = 35;
  epoch_packet_thresh_ = 80;
  epoch_packet_arrival_ = 0;
  epoch_packet_processed_ = 0;
  epoch_packet_queued_ = 0;
  epoch_flow_cache_.clear();
  per_flow_states_.clear();
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
  for (auto &it : per_flow_states_) {
    if (it.second != nullptr) {
      free(it.second);
      it.second = nullptr;
    }
  }

  per_flow_states_.clear();
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

/* Get a batch from NIC and send it to downstream */
struct task_result NFVCore::RunTask(Context *ctx, bess::PacketBatch *batch,
                                     void *arg) {
  Port *p = port_;

  const queue_t qid = (queue_t)(uintptr_t)arg;
  const int burst = ACCESS_ONCE(burst_);

  // Read the CPU cycle counter for better accuracy
  curr_ts_ns_ = tsc_to_ns(rdtsc());

  // Busy pulling from the NIC queue
  while (1) {
    // Should check llring_free_count(queue_)
    batch->set_cnt(p->RecvPackets(qid, batch->pkts(), 32));
    if (batch->cnt()) {
      // Note: need to consider possible drops due to |queue_| overflow
      llring_sp_enqueue_burst(queue_, (void **)batch->pkts(), batch->cnt());

      // To update |per_flow_states_|, |epoch_flow_cache_|, |epoch_packet_arrival_|
      UpdateStatsOnFetchBatch(batch);
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

  uint64_t total_bytes = 0;
  for (uint32_t i = 0; i < cnt; i++) {
    total_bytes += batch->pkts()[i]->total_len();
  }

  UpdateStatsPreProcessBatch(batch);

  ProcessBatch(ctx, batch);

  UpdateStatsPostProcessBatch(batch);

  return {.block = false,
          .packets = cnt,
          .bits = (total_bytes + cnt * 24) * 8};
}

void NFVCore::UpdateStatsOnFetchBatch(bess::PacketBatch *batch) {
  Flow flow;
  FlowState *state = nullptr;

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    if (!ParseFlowFromPacket(&flow, pkt)) {
      continue;
    }

    // Update per-core flow states
    auto state_it = per_flow_states_.find(flow);
    if (state_it == per_flow_states_.end()) {
      state = new FlowState();
      per_flow_states_.emplace(flow, state);
    } else {
      state = state_it->second;
    }

    state->ingress_packet_count += 1;
    if (state->short_epoch_packet_count == 0) {
      // Update the per-epoch flow count
      epoch_flow_cache_.emplace(flow, state);
    }
    state->short_epoch_packet_count += 1;

    // Append the pointer of this flow's stats
    set_attr<FlowState*>(this, flow_stats_attr_id_, pkt, state);
  }

  // Update per-epoch packet counter
  epoch_packet_arrival_ += cnt;
}

void NFVCore::UpdateStatsPreProcessBatch(bess::PacketBatch *batch) {
  using bess::utils::all_local_core_stats;
  Flow flow;
  FlowState *state = nullptr;

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    state = get_attr<FlowState*>(this, flow_stats_attr_id_, pkt);
    if (state == nullptr) {
      continue;
    }

    state->egress_packet_count += 1;

    // Update RSS bucket packet counters.
    uint32_t id = bess::utils::bucket_stats.RSSHashToID(reinterpret_cast<rte_mbuf*>(pkt)->hash.rss);

    bess::utils::bucket_stats.bucket_table_lock.lock_shared();
    bess::utils::bucket_stats.per_bucket_packet_counter[id] += 1;
    bess::utils::bucket_stats.bucket_table_lock.unlock_shared();
  }

  // Update per-epoch packet counter
  epoch_packet_processed_ += cnt;
  epoch_packet_queued_ = llring_count(queue_);

  // Update for NFVMonitor (the current epoch info)
  all_local_core_stats[core_id_]->active_flow_count = epoch_flow_cache_.size();
  all_local_core_stats[core_id_]->packet_rate = epoch_packet_arrival_;
  all_local_core_stats[core_id_]->packet_processed = epoch_packet_processed_;
  all_local_core_stats[core_id_]->packet_queued = epoch_packet_queued_;
}

void NFVCore::UpdateStatsPostProcessBatch(bess::PacketBatch *) {
  // If a new epoch starts, absorb the current packet queue
  ShortEpochProcess();
}

/* Get a batch from upstream */
void NFVCore::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  RunNextModule(ctx, batch);
}

bool NFVCore::ShortEpochProcess() {
  using bess::utils::all_core_stats_chan;

  bool is_new_epoch = (all_core_stats_chan[core_id_]->Size() > 0);

  if (is_new_epoch) {
    // At the end of one epoch, NFVCore requests software queues to
    // absorb the existing packet queue in the coming epoch.

    // |epoch_flow_cache_| has all flows that have arrivals in this epoch
    // |flow_to_sw_q_| has all flows that are offloaded to reserved cores
    // |sw_q_mask_| has all software queues that borrowed from NFVCtrl
    //
    // Flow Assignment Algorithm: (Greedy) first-fit
    // 0) check whether the NIC queue cannot be handled by NFVCore in the next epoch
    // 1) update |unoffload_flows_|
    // 2) update |sw_q| for packet room for in-use software queues
    // 3) If |unoffload_flows_| need to be offloaded:
    // - a) to decide the number of additional software queues to borrow
    // - b) to assign flows to new software queues
    // 4) If |sw_q| has more packets than |epoch_packet_thresh_|?
    // - a) handle overloaded software queues
    // 5) Split the NF chain to deal with super-bursty flows
    // 6) release idle software queues if they have not been used for N epochs

    // Update |unoffload_flows_|
    for (auto &it : epoch_flow_cache_) {
      it.second->queued_packet_count = it.second->ingress_packet_count - it.second->egress_packet_count;
      if (it.second == nullptr || flow_to_sw_q_.find(it.first) != flow_to_sw_q_.end()) {
        unoffload_flows_.emplace(it.first, it.second);
      }
    }

    // Check qlen of exisitng software queues
    for (auto &sw_q_it : sw_q_) {
      sw_q_it.assigned_packet_count = llring_count(sw_q_it.sw_q);
    }

    // Greedy assignment: first-fit
    auto flow_it = unoffload_flows_.begin();
    while (flow_it != unoffload_flows_.end()) {
      uint32_t task_size = flow_it->second->queued_packet_count;
      if (task_size <= epoch_packet_thresh_) {
        for (auto &sw_q_it : sw_q_) {
          if (sw_q_it.QLenAfterAssignment() + task_size < epoch_packet_thresh_) {
            flow_it->second->sw_q_id = sw_q_it.sw_q_id;
            sw_q_it.assigned_packet_count += task_size;
            break;
          }
        }

        flow_it = unoffload_flows_.erase(flow_it);
      } else {
        flow_it++;
      }
    }

    // Determine the number of software queues to borrow / return.

    unoffload_flows_.clear();

    CoreStats* stats_ptr = nullptr;
    while (all_core_stats_chan[core_id_]->Size()) {
      all_core_stats_chan[core_id_]->Pop(stats_ptr);
      delete (stats_ptr);
      stats_ptr = nullptr;

      epoch_flow_thresh_ = 35;
      epoch_packet_thresh_ = 80;
    }

    epoch_flow_cache_.clear();
    epoch_packet_arrival_ = 0;
    epoch_packet_processed_ = 0;

    return true;
  }

  return false;
}

ADD_MODULE(NFVCore, "nfv_core", "It handles traffic burstiness at a normal core")
