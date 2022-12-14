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
      if (q_state == &system_dump_q0_) {
        // Egress 1: drop (no sw_q)
        state->queued_packet_count -= 1;
        local_rboost_batch_->add(pkt);
        // epoch_drop1_ += 1;
        continue;
      }
      if (q_state == &system_dump_q1_) {
        // Egress 2: drop (super flow)
        state->queued_packet_count -= 1;
        local_rboost_batch_->add(pkt);
        // epoch_drop4_ += 1;
        continue;
      }
      if (q_state->idle_epoch_count == -1) {
        /// Option 1: drop
        // Egress 3: drop (idle RCore)
        // Do not offload because RCore is inactive.
        // state->sw_q_state = &system_dump_q1_;
        // state->queued_packet_count -= 1;
        // bess::Packet::Free(pkt);
        // epoch_drop2_ += 1;

        /// Option 2: go back to ncore
        // state->sw_q_state = nullptr;
        // local_batch_->add(pkt);
        // continue;

        /// Option 3: recruit another core
        int ret = bess::ctrl::NFVCtrlNotifyRCoreToWork(core_id_, q_state->sw_q_id);
        if (ret == 0) {
          q_state->idle_epoch_count = 0;
          curr_rcore_ += 1;
        }
      }

      // Add debugg per-packet tags for sw enqueue
      // if (add_debug_tag_nfvcore) {
      //   uint32_t val;
      //   val = q_state->idle_epoch_count >= 0 ? q_state->idle_epoch_count : 1000000;
      //   TagUint32(pkt, 90, val);
      //   val = core_id_ * 1000 + q_state->sw_q_id;
      //   TagUint32(pkt, 94, val);
      //   val = llring_count(q_state->sw_q);
      //   TagUint32(pkt, 98, val);
      // }

      // Egress 4: normal offloading
      // This flow is redirected only if an active RCore works on |sw_q|
      state->queued_packet_count -= 1;
      q_state->sw_batch->add(pkt);
      continue;
    }

    local_batch_->add(pkt);
  }

  // Update per-epoch packet counter
  epoch_packet_arrival_ += cnt;

  // Egress 5: drop (|local_q_| overflow)
  SpEnqueue(local_batch_, local_q_);
  MpEnqueue(local_rboost_batch_, bess::ctrl::system_dump_q_);
  for (auto& sw_q_it : sw_q_) {
    sw_q_it.EnqueueBatch();
  }
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
  if (bess::ctrl::exp_id == 1) {
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
  if (total_cnt <= epoch_packet_thresh_) {
    return;
  }

  bess::PacketBatch batch;
  uint32_t curr_cnt = 0;
  while (curr_cnt < total_cnt) { // scan all packets only once
    batch.clear();
    int cnt = llring_mc_dequeue_burst(q, (void **)batch.pkts(), 32);
    batch.set_cnt(cnt);
    SplitAndEnqueue(&batch);
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
      if (q_state == &system_dump_q0_) {
        // Egress 7: drop (no sw_q)
        state->queued_packet_count -= 1;
        local_rboost_batch_->add(pkt);
        // epoch_drop1_ += 1;
        continue;
      }
      if (q_state == &system_dump_q1_) {
        // Egress 8: drop (super flow)
        state->queued_packet_count -= 1;
        local_rboost_batch_->add(pkt);
        // epoch_drop4_ += 1;
        continue;
      }
      if (q_state->idle_epoch_count == -1) {
        /// Option 1: drop
        // Egress 9: drop (idle RCore)
        // state->sw_q_state = &system_dump_q1_;
        // state->queued_packet_count -= 1;
        // bess::Packet::Free(pkt);
        // epoch_drop2_ += 1;

        /// Option 2: go back to ncore
        // state->sw_q_state = nullptr;
        // local_batch_->add(pkt);

        /// Option 3: recruit another core
        int ret = bess::ctrl::NFVCtrlNotifyRCoreToWork(core_id_, q_state->sw_q_id);
        if (ret == 0) {
          q_state->idle_epoch_count = 0;
          curr_rcore_ += 1;
        }
      }

      // Egress 10: normal offloading
      // This flow is redirected only if an active RCore works on |sw_q|.
      state->queued_packet_count -= 1;
      q_state->sw_batch->add(pkt);
      continue;
    }

    state->enqueued_packet_count += 1;
    local_batch_->add(pkt);
  }

  // Just drop excessive packets when a software queue is full
  // Egress 11: drop (|local_q_| overflow)
  SpEnqueue(local_batch_, local_q_);
  MpEnqueue(local_rboost_batch_, bess::ctrl::system_dump_q_);
  for (auto& sw_q_it : sw_q_) {
    sw_q_it.EnqueueBatch();
  }
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
  //
  // |epoch_flow_cache_| has all flows that have arrivals in this epoch
  // |flow_to_sw_q_| has all flows that are offloaded to reserved cores
  // |sw_q_mask_| has all software queues that borrowed from NFVCtrl
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
    if (bess::ctrl::sw_q_state[q->sw_q_id]->GetDownCoreID() == DEFAULT_INVALID_CORE_ID) {
      q->idle_epoch_count = -2;
      q->assigned_packet_count = 0;
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
  uint32_t local_large_flow = 0;
  uint32_t local_flow_count = epoch_flow_cache_.size();
  uint32_t local_pkt_thresh = GetMaxPktCountFromShortTermProfile(local_flow_count) - 32;
  uint32_t local_pkt_assigned = 0;

  for (auto it = unoffload_flows_.begin(); it != unoffload_flows_.end(); ++it) {
    FlowState *state = *it;
    uint32_t task_size = state->queued_packet_count;

    if (task_size <= local_pkt_thresh) {
      if (local_pkt_assigned + task_size < local_pkt_thresh) {
        local_pkt_assigned += task_size;
      } else {
        // Prioritize sw queues that are active.
        bool assigned = false;
        for (auto qit = active_sw_q_.begin(); qit != active_sw_q_.end(); ++qit) {
          SoftwareQueueState* q = *qit;
          if (q->QLenAfterAssignment() + task_size < epoch_packet_thresh_) {
            state->sw_q_state = q;
            q->assigned_packet_count += task_size;
            assigned = true;
            break;
          }
        }

        if (!assigned) {
          for (auto qit = idle_sw_q_.begin(); qit != idle_sw_q_.end(); ++qit) {
            SoftwareQueueState* q = *qit;
            if (q->QLenAfterAssignment() + task_size < epoch_packet_thresh_) {
              state->sw_q_state = q;
              q->assigned_packet_count += task_size;
              assigned = true;
              break;
            }
          }

          // Existing software queues cannot hold this flow. Need more queues
          if (!assigned) {
            state->sw_q_state = &system_dump_q0_;
          }
        }
      }
    } else {
      // This flow cannot be handled by only 1 core.
      local_large_flow += task_size;
      state->sw_q_state = &system_dump_q1_;
    }
  }

  LOG(INFO) << active_sw_q_.size() << ", " << terminating_sw_q_.size() << ", " idle_sw_q_.size();

  // Reclaim idle rcores
  int ret;
  for (auto qit = active_sw_q_.begin(); qit != active_sw_q_.end(); ) {
    SoftwareQueueState* q = *qit;
    q->processed_packet_count = 0;

    if (q->idle_epoch_count >= max_idle_epoch_count_) { // idle for a while
      ret = bess::ctrl::NFVCtrlNotifyRCoreToRest(core_id_, q->sw_q_id);
      if (ret != 0) {
        LOG(ERROR) << "E error: " << ret << "; core: " << core_id_ << "; q: " << q->sw_q_id;
      } else {
        curr_rcore_ -= 1;
      }
      q->idle_epoch_count = -1; // terminating
      active_sw_q_.erase(qit++);
      terminating_sw_q_.emplace(q);
    } else {
      ++qit;
    }    
  }

  // Activate rcores to do the work
  for (auto qit = idle_sw_q_.begin(); qit != idle_sw_q_.end(); ) {
    SoftwareQueueState* q = *qit;
    q->processed_packet_count = 0;

    if (q->assigned_packet_count > 0) { // got things to do
      ret = bess::ctrl::NFVCtrlNotifyRCoreToWork(core_id_, q->sw_q_id);
      if (ret != 0) {
        LOG(ERROR) << "S error: " << ret << "; core: " << core_id_ << "; q: " << q->sw_q_id;
      } else {
        curr_rcore_ += 1;
      }
      q->idle_epoch_count = 0;
      idle_sw_q_.erase(qit++);
      active_sw_q_.emplace(q);
    } else {
      ++qit;
    }
  }

  // Clear
  epoch_flow_cache_.clear();
  if (bess::ctrl::exp_id == 1) {
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
