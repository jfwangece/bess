#include "nfv_core.h"
#include "nfv_ctrl.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/udp.h"
#include "../utils/packet_tag.h"
#include "../utils/sys_measure.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;
using bess::utils::Udp;
using bess::utils::TagUint32;
using bess::utils::add_debug_tag_nfvcore;

namespace {
} // namespace

void NFVCore::UpdateBucketStats() {
  update_bucket_stats_ = true;
}

void NFVCore::UpdateStatsOnFetchBatch(bess::PacketBatch *batch) {
  Flow flow;
  FlowState *state = nullptr;

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    if (!bess::utils::ParseFlowFromPacket(&flow, pkt)) {
      // After this line, all packets must be associated with a flow.
      bess::Packet::Free(pkt);
      continue;
    }

    // Update per-core flow states
    auto state_it = per_flow_states_.Find(flow);
    if (state_it == nullptr) {
      // Init a flow
      state = new FlowState();
      state->flow = flow;
      state->rss = bess::utils::bucket_stats->RSSHashToID(reinterpret_cast<rte_mbuf*>(pkt)->hash.rss);
      state->sw_q_state = nullptr;
      per_flow_states_.Insert(flow, state);
    } else {
      state = state_it->second;
    }

    // Append flow's stats pointer to pkt's metadata
    *(_ptr_attr_with_offset<FlowState*>(this->attr_offset(flow_stats_attr_id_), pkt)) = state;
    // LOG(INFO) << "set: " << *(_ptr_attr_with_offset<FlowState*>(this->attr_offset(flow_stats_attr_id_), pkt));

    // update per-bucket packet counter and per-bucket flow cache.
    uint32_t id = state->rss;
    local_bucket_stats_.per_bucket_packet_counter[id] += 1;

    if (state->short_epoch_packet_count == 0) {
      // Update the per-epoch flow count
      local_bucket_stats_.per_bucket_flow_cache[id].emplace(state->flow, true);
      epoch_flow_cache_.emplace(state);
    }
    state->short_epoch_packet_count += 1;
    state->queued_packet_count += 1;

    // Determine the packet's destination queue
    auto& q_state = state->sw_q_state;
    if (q_state != nullptr) {
      if (q_state == system_dump_q_state_) {
        // Egress 1: drop (no sw_q)
        state->queued_packet_count -= 1;
        system_dump_batch_->add(pkt);
        // epoch_drop1_ += 1;
        continue;
      }
      if (q_state == rcore_booster_q_state_) {
        // Egress 2: drop (super flow)
        state->queued_packet_count -= 1;
        local_rboost_batch_->add(pkt);
        // epoch_drop4_ += 1;
        continue;
      }
      if (active_sw_q_.find(state->sw_q_state) == active_sw_q_.end()) {
        /// Option 1: go back to ncore
        state->sw_q_state = nullptr;
        local_batch_->add(pkt);
        continue;
      }

      // Egress 4: normal offloading
      // This flow is redirected only if an active RCore works on |sw_q|
      state->queued_packet_count -= 1;
      local_sw_batch_[q_state->sw_q_id]->add(pkt);
      continue;
    }

    local_batch_->add(pkt);
  }

  // Update per-epoch packet counter
  epoch_packet_arrival_ += cnt;

  // Egress 5: drop (|local_q_| overflow)
  SpEnqueue(local_batch_, local_q_);
  for (auto& q : active_sw_q_) {
    MpEnqueue(local_sw_batch_[q->sw_q_id], q->sw_q);
  }
  MpEnqueue(local_rboost_batch_, bess::ctrl::rcore_boost_q);
  MpEnqueue(system_dump_batch_, bess::ctrl::system_dump_q);
}

void NFVCore::UpdateStatsPreProcessBatch(bess::PacketBatch *batch) {
  FlowState *state = nullptr;
  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    // Note: no need to parse |flow| again because we've parsed it first.
    // Update per-flow packet counter.
    state = *(_ptr_attr_with_offset<FlowState*>(this->attr_offset(flow_stats_attr_id_), pkt));
    state->queued_packet_count -= 1;
  }

  // Update for NFVMonitor (the current epoch info)
  if (bess::ctrl::exp_id == 2) {
    // Update per-epoch packet counter
    epoch_packet_processed_ += cnt;
    epoch_packet_queued_ = llring_count(local_q_);

    using bess::utils::all_local_core_stats;
    all_local_core_stats[core_id_]->active_flow_count = epoch_flow_cache_.size();
    all_local_core_stats[core_id_]->packet_rate = epoch_packet_arrival_;
    all_local_core_stats[core_id_]->packet_processed = epoch_packet_processed_;
    all_local_core_stats[core_id_]->packet_queued = epoch_packet_queued_;
  }
}

void NFVCore::SplitQToSwQ(llring* q) {
  uint32_t total_cnt = llring_count(q);

  uint32_t curr_cnt = 0;
  while (curr_cnt < total_cnt) { // scan all packets only once
    split_enqueue_batch_->clear();
    int cnt = llring_sc_dequeue_burst(q, (void **)split_enqueue_batch_->pkts(), 32);
    split_enqueue_batch_->set_cnt(cnt);
    SplitAndEnqueue(split_enqueue_batch_);
    curr_cnt += cnt;
  }

  // Debug log (unresolved)
  // if (llring_count(q) > epoch_packet_thresh_) {
  //   LOG(INFO) << "splitQ: error (large local_queue=" << llring_count(local_q_) << ", core=" << core_id_ << ")";
  // }
}

// Split a batch of packets and respect pre-determined flow-affinity
void NFVCore::SplitAndEnqueue(bess::PacketBatch* batch) {
  FlowState* state;
  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    state = *(_ptr_attr_with_offset<FlowState*>(this->attr_offset(flow_stats_attr_id_), pkt));

    auto& q_state = state->sw_q_state;
    if (q_state != nullptr) {
      if (q_state == system_dump_q_state_) {
        // Egress 7: drop (no sw_q)
        state->queued_packet_count -= 1;
        system_dump_batch_->add(pkt);
        // epoch_drop1_ += 1;
        continue;
      }
      if (q_state == rcore_booster_q_state_) {
        // Egress 8: drop (super flow)
        state->queued_packet_count -= 1;
        local_rboost_batch_->add(pkt);
        // epoch_drop4_ += 1;
        continue;
      }
      if (active_sw_q_.find(state->sw_q_state) == active_sw_q_.end()) {
        /// Option 1: go back to ncore
        state->sw_q_state = nullptr;
        local_batch_->add(pkt);
        continue;
      }

      // Egress 10: normal offloading
      // This flow is redirected only if an active RCore works on |sw_q|.
      state->queued_packet_count -= 1;
      local_sw_batch_[q_state->sw_q_id]->add(pkt);
      continue;
    }

    // state->enqueued_packet_count += 1;
    local_batch_->add(pkt);
  }

  // Just drop excessive packets when a software queue is full
  // Egress 11: drop (|local_q_| overflow)
  SpEnqueue(local_batch_, local_q_);
  for (auto& q : active_sw_q_) {
    MpEnqueue(local_sw_batch_[q->sw_q_id], q->sw_q);
  }
  MpEnqueue(local_rboost_batch_, bess::ctrl::rcore_boost_q);
  MpEnqueue(system_dump_batch_, bess::ctrl::system_dump_q);
}

uint32_t GetMaxPktCountFromShortTermProfile(uint32_t fc) {
  if (bess::ctrl::short_flow_count_pkt_threshold.size() == 0) {
    return 512;
  }

  const auto& it = bess::ctrl::short_flow_count_pkt_threshold.find(fc);
  if (it != bess::ctrl::short_flow_count_pkt_threshold.end()) {
    return it->second;
  }
  return (--bess::ctrl::short_flow_count_pkt_threshold.end())->second;
}

bool NFVCore::ShortEpochProcess() {
  using bess::utils::all_core_stats_chan;

  // At the end of one epoch, NFVCore requests software queues to
  // absorb the existing packet queue in the coming epoch.
  // |epoch_flow_cache_| has all flows that have arrivals in this epoch
  //
  // Flow Assignment Algorithm: (Greedy) first-fit
  // 0) check whether the NIC queue cannot be handled by NFVCore in the next epoch
  //    - if the number of packets in |local_q_| is too large, then go to the next step;
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
  for (auto qit = active_sw_q_.begin(); qit != active_sw_q_.end(); ++qit) {
    SoftwareQueueState* q = *qit;
    if (q->processed_packet_count == 0) {
      q->idle_epoch_count += 1;
    } else {
      q->idle_epoch_count = 0;
    }
    q->assigned_packet_count = llring_count(q->sw_q);
  }

  for (auto qit = terminating_sw_q_.begin(); qit != terminating_sw_q_.end(); ) {
    SoftwareQueueState* q = *qit;
    if (bess::ctrl::sw_q_state[q->sw_q_id]->GetUpCoreID() == DEFAULT_INVALID_CORE_ID) {
      q->idle_epoch_count = -2; // terminated
      terminating_sw_q_.erase(qit++);
    } else {
      ++qit;
    }
  }

  // Update |unoffload_flows_|
  unoffload_flows_.clear();
  for (auto it = epoch_flow_cache_.begin(); it != epoch_flow_cache_.end(); ++it) {
    FlowState *state = *it;
    if (state != nullptr) {
      if (state->queued_packet_count > 10000) {
        // LOG(INFO) << "incorrect per-flow packet counter: " << state->queued_packet_count;
        state->queued_packet_count = 0;
      }

      // Reset so that the flow can be recorded in the next short epoch
      state->enqueued_packet_count = 0;
      state->short_epoch_packet_count = 0;

      // Skip flows that have been assigned to migrate to RCores
      if (state->sw_q_state != nullptr) {
        continue;
      }
      unoffload_flows_.emplace(state);
    } else {
      LOG(FATAL) << "short-term: error (impossible non-flow packet)";
    }
  }

  // Greedy assignment: first-fit
  uint32_t local_flow_count = epoch_flow_cache_.size();
  uint32_t local_pkt_thresh = GetMaxPktCountFromShortTermProfile(local_flow_count);
  uint32_t local_pkt_assigned = 0;

  for (auto it = unoffload_flows_.begin(); it != unoffload_flows_.end(); ++it) {
    FlowState *state = *it;
    uint32_t task_size = state->queued_packet_count;

    if (task_size <= epoch_packet_thresh_) {
      if (local_pkt_assigned + task_size < local_pkt_thresh) {
        local_pkt_assigned += task_size;
      } else {
        // Prioritize sw queues that are active.
        bool assigned = false;
        SoftwareQueueState* q = nullptr;
        for (auto qit = active_sw_q_.begin(); qit != active_sw_q_.end(); ++qit) {
          q = *qit;
          if (q->QLenAfterAssignment() + task_size < epoch_packet_thresh_) {
            state->sw_q_state = q;
            q->assigned_packet_count += task_size;
            assigned = true;
            break;
          }
        }

        if (!assigned) {
          int qid = bess::ctrl::nfv_ctrl->RequestRCore();
          if (qid != -1) {
            q = bess::ctrl::sw_q_state[qid];
            q->SetUpCoreID(core_id_);
            q->idle_epoch_count = 0;
            q->assigned_packet_count = task_size;

            active_sw_q_.emplace(q);
            curr_rcore_ += 1;
            state->sw_q_state = q;
            assigned = true;
            // LOG(INFO) << "core " << core_id_ << " gets q" << qid << ". rcores=" << active_sw_q_.size();
          } else {
            // All rcores are busy now! Need to clean this flow anyway.
            state->sw_q_state = system_dump_q_state_;
          }
        }
      }
    } else {
      // This flow cannot be handled by only 1 core.
      state->sw_q_state = rcore_booster_q_state_;
    }
  }

  // Reclaim idle rcores
  for (auto qit = active_sw_q_.begin(); qit != active_sw_q_.end(); ) {
    SoftwareQueueState* q = *qit;
    q->processed_packet_count = 0;

    if (q->idle_epoch_count >= max_idle_epoch_count_) { // idle for a while
      q->idle_epoch_count = -1; // terminating
      bess::ctrl::nfv_ctrl->ReleaseRCore(q->sw_q_id);

      active_sw_q_.erase(qit++);
      terminating_sw_q_.emplace(q);
      curr_rcore_ -= 1;
      // LOG(INFO) << "core " << core_id_ << " releases q" << q->sw_q_id << ". rcores=" << active_sw_q_.size();
    } else {
      ++qit;
    }
  }

  // if (core_id_ == 2) {
  //   LOG(INFO) << active_sw_q_.size() << ", " << terminating_sw_q_.size() << ", " << idle_sw_q_.size();
  // }

  // Clear
  epoch_flow_cache_.clear();
  if (bess::ctrl::exp_id == 2) {
    CoreStats* stats_ptr = nullptr;
    while (all_core_stats_chan[core_id_]->Size()) {
      all_core_stats_chan[core_id_]->Pop(stats_ptr);
      delete (stats_ptr);
    }
    epoch_packet_arrival_ = 0;
    epoch_packet_processed_ = 0;
  }

  return true;
}
