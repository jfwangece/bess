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
  struct llring *old_queue = local_queue_;
  struct llring *new_queue;

  int bytes = llring_bytes_with_slots(slots);

  new_queue =
      reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));
  if (!new_queue) {
    return -ENOMEM;
  }

  int ret = llring_init(new_queue, slots, 1, 1);
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

  local_queue_ = new_queue;
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
    local_batch_ = reinterpret_cast<bess::PacketBatch *>
          (std::aligned_alloc(alignof(bess::PacketBatch), sizeof(bess::PacketBatch)));
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
  bess::ctrl::nfv_cores[core_id_] = this;

  // Begin with 0 software queue
  sw_q_mask_ = bess::ctrl::NFVCtrlRequestNSwQ(core_id_, 4);
  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    uint64_t sw_q_idx = (1ULL << i) & sw_q_mask_;
    if (sw_q_idx != 0) {
      sw_q_.emplace_back (i);
      sw_q_.back().sw_batch = reinterpret_cast<bess::PacketBatch *>
          (std::aligned_alloc(alignof(bess::PacketBatch), sizeof(bess::PacketBatch)));
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

  // Run!
  rte_atomic16_set(&disabled_, 0);
  return CommandSuccess();
}

void NFVCore::DeInit() {
  rte_atomic16_set(&disabled_, 1);

  bess::Packet *pkt;
  // Clean the local software queue
  if (local_queue_) {
    while (llring_sc_dequeue(local_queue_, (void **)&pkt) == 0) {
      bess::Packet::Free(pkt);
    }
    std::free(local_queue_);
    local_queue_ = nullptr;
  }
  if (local_batch_) {
    bess::Packet::Free(local_batch_);
    std::free(local_batch_);
    local_batch_ = nullptr;
  }

  // Clean (borrowed) software queues
  bess::ctrl::NFVCtrlReleaseNSwQ(core_id_, sw_q_mask_);
  LOG(INFO) << "Core " << core_id_ << " releases " << sw_q_.size() << " sw_q. q_mask: " << std::bitset<64> (sw_q_mask_);

  for (auto &it : sw_q_) {
    it.sw_q = nullptr;
    if (it.sw_batch) {
      bess::Packet::Free(it.sw_batch);
      std::free(it.sw_batch);
      it.sw_batch = nullptr;
    }
  }
  sw_q_.clear();
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
  return bess::utils::Format("%s:%hhu/%d", port_->name().c_str(), qid_, llring_count(local_queue_));
}

/* Get a batch from NIC and send it to downstream */
struct task_result NFVCore::RunTask(Context *ctx, bess::PacketBatch *batch,
                                     void *arg) {
  if(rte_atomic16_read(&disabled_) != 0) {
    return {.block = false, .packets = 0, .bits = 0};
  }

  Port *p = port_;
  const queue_t qid = (queue_t)(uintptr_t)arg;
  const int burst = ACCESS_ONCE(burst_);

  // Read the CPU cycle counter for better accuracy
  curr_ts_ns_ = tsc_to_ns(rdtsc());

  // Busy pulling from the NIC queue
  while (1) {
    batch->set_cnt(p->RecvPackets(qid, batch->pkts(), 32));
    if (batch->cnt()) {
      // To append |per_flow_states_|
      // Update the number of packets / flows that have arrived:
      // Update |epoch_packet_arrival_| and |epoch_flow_cache_|
      UpdateStatsOnFetchBatch(batch);
    }

    if (batch->cnt() < 30) {
      break;
    }
  }

  // Process one batch
  uint32_t cnt = llring_sc_dequeue_burst(local_queue_, (void **)batch->pkts(), burst);
  if (cnt == 0) {
    // Call PostProcessBatch here.
    return {.block = false, .packets = 0, .bits = 0};
  }
  batch->set_cnt(cnt);

  uint64_t total_bytes = 0;
  for (uint32_t i = 0; i < cnt; i++) {
    total_bytes += batch->pkts()[i]->total_len();
  }

  // Update the number of packets / flows processed:
  // |epoch_packet_processed_| and |per_flow_states_|
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

  local_batch_->clear();
  for (auto &sw_q_it : sw_q_) {
    sw_q_it.sw_batch->clear();
  }

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

    if (state->sw_q_state) {
      state->sw_q_state->sw_batch->add(pkt);
    } else {
      local_batch_->add(pkt);
    }

    // Append the pointer of this flow's stats
    set_attr<FlowState*>(this, flow_stats_attr_id_, pkt, state);
  }

  // Update per-epoch packet counter
  epoch_packet_arrival_ += cnt;

  // Just drop excessive packets when a software queue is full
  if (local_batch_->cnt()) {
    int queued = llring_sp_enqueue_burst(local_queue_, (void **)local_batch_->pkts(), local_batch_->cnt());
    if (queued < 0) {
      queued = queued & (~RING_QUOT_EXCEED);
    }
    if (queued < local_batch_->cnt()) {
      int to_drop = local_batch_->cnt() - queued;
      bess::Packet::Free(local_batch_->pkts() + queued, to_drop);
    }
  }
  for (auto &sw_q_it : sw_q_) {
    sw_q_it.EnqueueBatch();
  }
}

void NFVCore::UpdateStatsPreProcessBatch(bess::PacketBatch *batch) {
  using bess::utils::all_local_core_stats;
  Flow flow;
  FlowState *state = nullptr;

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    // Update per-bucket packet counter.
    uint32_t id = bess::utils::bucket_stats->RSSHashToID(reinterpret_cast<rte_mbuf*>(pkt)->hash.rss);
    bess::utils::bucket_stats->bucket_table_lock.lock_shared();
    bess::utils::bucket_stats->per_bucket_packet_counter[id] += 1;
    bess::utils::bucket_stats->bucket_table_lock.unlock_shared();

    // Update per-flow packet counter.
    state = get_attr<FlowState*>(this, flow_stats_attr_id_, pkt);
    if (state == nullptr) {
      continue;
    }
    state->egress_packet_count += 1;
  }

  // Update per-epoch packet counter
  epoch_packet_processed_ += cnt;
  epoch_packet_queued_ = llring_count(local_queue_);

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
    //    - if the number of packets in |local_queue_| is too large, then go to the next step;
    //    - otherwise, stop here;
    // 1) update |sw_q| for packet room for in-use software queues
    // 2) update |unoffload_flows_|
    //    if |unoffload_flows_| is empty, stop here;
    // 3) If |unoffload_flows_| need to be offloaded:
    //    - a) to decide the number of additional software queues to borrow
    //    - b) to assign flows to new software queues
    // 4) If |sw_q| has more packets than |epoch_packet_thresh_|?
    //    - a) handle overloaded software queues
    // 5) Split the NF chain to deal with super-bursty flows
    // 6) release idle software queues if they have not been used for N epochs

    // Check qlen of exisitng software queues
    for (auto &sw_q_it : sw_q_) {
      if (sw_q_it.processed_packet_count == 0) {
        sw_q_it.idle_epoch_count += 1;
      }
      sw_q_it.assigned_packet_count = llring_count(sw_q_it.sw_q);
    }

    // Update |unoffload_flows_|
    for (auto &it : epoch_flow_cache_) {
      if (it.second != nullptr) {
        it.second->queued_packet_count = it.second->ingress_packet_count - it.second->egress_packet_count;
        if (it.second->sw_q_state != nullptr) {
          // flows that have been assigned
          continue;
        }
      }
      unoffload_flows_.emplace(it.first, it.second);
    }

    // Greedy assignment: first-fit
    uint32_t local_assigned = 0;
    auto flow_it = unoffload_flows_.begin();
    while (flow_it != unoffload_flows_.end()) {
      uint32_t task_size = flow_it->second->queued_packet_count;
      if (task_size <= epoch_packet_thresh_) {
        if (local_assigned + task_size < epoch_packet_thresh_) {
          local_assigned += task_size;
          flow_it = unoffload_flows_.erase(flow_it);
        } else {
          bool assigned = false;
          for (auto &sw_q_it : sw_q_) {
            if (sw_q_it.QLenAfterAssignment() + task_size < epoch_packet_thresh_) {
              flow_it->second->sw_q_state = &sw_q_it;
              sw_q_it.assigned_packet_count += task_size;
              flow_it = unoffload_flows_.erase(flow_it);
              assigned = true;
              break;
            }
          }
          if (!assigned) { // need more software queues (current ones cannot hold this flow)
            // LOG(ERROR) << "Core " << core_id_ << " runs out of sw_q";
            flow_it++;
          }
        }
      } else {
        flow_it++;
      }
    }

    // Notify reserved cores to do the work.
    int ret;
    for (auto &sw_q_it : sw_q_) {
      if (sw_q_it.idle_epoch_count > 0 &&
          sw_q_it.assigned_packet_count > 0) { // got things to do
        ret = bess::ctrl::NFVCtrlNotifyRCoreToWork(core_id_, sw_q_it.sw_q_id);
        if (ret == 0) {
          LOG(INFO) << "S Core: " << core_id_ << ". RCore: " << sw_q_it.sw_q_id;
        } else {
          LOG(ERROR) << "S " << ret;
        }
        sw_q_it.idle_epoch_count = 0;
      } else {
        // |idle_epoch_count| == 0 || |assigned_packet_count| == 0
        if (sw_q_it.idle_epoch_count >= 10) { // idle for a while
          ret = bess::ctrl::NFVCtrlNotifyRCoreToRest(core_id_, sw_q_it.sw_q_id);
          if (ret == 0) {
            LOG(INFO) << "E Core: " << core_id_ << " stops RCore: " << sw_q_it.sw_q_id;
          } else {
            LOG(ERROR) << "E " << ret;
          }
        }
      }
      sw_q_it.processed_packet_count = 0;
    }

    // Handle super-bursty flows by splitting a chain into several cores
    unoffload_flows_.clear();

    // Clear
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
