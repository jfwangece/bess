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

void NFVCore::UpdateStatsOnFetchBatch(bess::PacketBatch *batch) {
  Flow flow;
  FlowState *state = nullptr;

  local_batch_->clear();
  for (auto& sw_q_it : sw_q_) {
    sw_q_it.sw_batch->clear();
  }

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    if (!bess::utils::ParseFlowFromPacket(&flow, pkt)) {
      // For now, we handle L4 packets only.
      // After this line, all packets must be associated with a flow.
      bess::Packet::Free(pkt);
      continue;
    }

    // Update per-core flow states
    auto state_it = per_flow_states_.find(flow);
    if (state_it == per_flow_states_.end()) {
      state = new FlowState();
      state->flow = flow;
      state->rss = bess::utils::bucket_stats->RSSHashToID(reinterpret_cast<rte_mbuf*>(pkt)->hash.rss);
      state->ingress_packet_count = 0;
      state->egress_packet_count = 0;
      per_flow_states_.emplace(flow, state);
    } else {
      state = state_it->second;
    }

    // Append flow's stats pointer to pkt's metadata
    *(_ptr_attr_with_offset<FlowState*>(this->attr_offset(flow_stats_attr_id_), pkt)) = state;
    // LOG(INFO) << "set: " << *(_ptr_attr_with_offset<FlowState*>(this->attr_offset(flow_stats_attr_id_), pkt));

    if (state->short_epoch_packet_count == 0) {
      // Update the per-epoch flow count
      epoch_flow_cache_.emplace(state);
    }
    state->short_epoch_packet_count += 1;
    state->ingress_packet_count += 1;

    // Determine the packet's destination queue
    auto& q_state = state->sw_q_state;
    if (q_state != nullptr) {
      if (q_state == &system_dump_q0_) {
        // Egress 1: drop (no sw_q)
        if (state->ingress_packet_count > state->egress_packet_count) {
          state->egress_packet_count += 1;
        }
        bess::Packet::Free(pkt);
        epoch_drop1_ += 1;
        continue;
      }
      if (q_state == &system_dump_q1_) {
        // Egress 2: drop (super flow)
        if (state->ingress_packet_count > state->egress_packet_count) {
          state->egress_packet_count += 1;
        }
        bess::Packet::Free(pkt);
        epoch_drop4_ += 1;
        continue;
      }

      if (q_state->idle_epoch_count == -1) {
        // Egress 3: drop (idle RCore)
        // Do not offload because RCore is inactive. Reset the offloading.
        state->sw_q_state = &system_dump_q1_;

        if (state->ingress_packet_count > state->egress_packet_count) {
          state->egress_packet_count += 1;
        }
        bess::Packet::Free(pkt);
        epoch_drop2_ += 1;
        continue;
      }

      // Add debugging packet tags
      if (add_debug_tag_nfvcore) {
        uint32_t val;
        val = q_state->idle_epoch_count >= 0 ? q_state->idle_epoch_count : 1000000;
        TagUint32(pkt, 90, val);
        val = core_id_ * 1000 + q_state->sw_q_id;
        TagUint32(pkt, 94, val);
        val = llring_count(q_state->sw_q);
        TagUint32(pkt, 98, val);
      }

      // Egress 4: normal offloading
      // This flow is redirected only if an active RCore works on |sw_q|
      if (state->ingress_packet_count > state->egress_packet_count) {
        state->egress_packet_count += 1;
      }
      q_state->sw_batch->add(pkt);
      continue;
    }

    local_batch_->add(pkt);
  }

  // Update per-epoch packet counter
  epoch_packet_arrival_ += cnt;

  // Just drop excessive packets when a software queue is full
  // Egress 5: drop (|local_queue_| overflow)
  BestEffortEnqueue(local_batch_, local_queue_);
  for (auto& sw_q_it : sw_q_) {
    sw_q_it.EnqueueBatch();
  }
}

void NFVCore::UpdateStatsPreProcessBatch(bess::PacketBatch *batch) {
  using bess::utils::all_local_core_stats;
  FlowState *state = nullptr;

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    // Note: no need to parse |flow| again because we've parsed it first.
    // Update per-flow packet counter.
    state = *(_ptr_attr_with_offset<FlowState*>(this->attr_offset(flow_stats_attr_id_), pkt));
    uint32_t id = state->rss;

    // Egress 6: normal processing
    if (state->ingress_packet_count > state->egress_packet_count) {
      state->egress_packet_count += 1;
    }

    // update per-bucket packet counter and per-bucket flow cache.
    bess::utils::bucket_stats->bucket_table_lock.lock_shared();
    bess::utils::bucket_stats->per_bucket_packet_counter[id] += 1;
    bess::utils::bucket_stats->per_bucket_flow_cache[id].emplace(state->flow, true);
    bess::utils::bucket_stats->bucket_table_lock.unlock_shared();
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

void NFVCore::SplitQToSwQ(llring* q) {
  uint32_t total_cnt = llring_count(q);
  if (total_cnt <= epoch_packet_thresh_) {
    return;
  }

  bess::PacketBatch batch;
  uint32_t curr_cnt = 0;
  while (curr_cnt < total_cnt) { // scan all packets only once
    batch.clear();
    int cnt = llring_sc_dequeue_burst(q, (void **)batch.pkts(), 32);
    batch.set_cnt(cnt);

    // bess::Packet::Free(&batch);
    SplitAndEnqueue(&batch);
    curr_cnt += cnt;
  }
  // Debug log
  if (llring_count(q) > epoch_packet_thresh_) {
    LOG(INFO) << "splitQ: error (large local_queue=" << llring_count(local_queue_) << ", core=" << core_id_ << ")";
  }
}

// Split a batch of packets and respect pre-determined flow-affinity
void NFVCore::SplitAndEnqueue(bess::PacketBatch* batch) {
  local_batch_->clear();
  for (auto& sw_q_it : sw_q_) {
    sw_q_it.sw_batch->clear();
  }

  FlowState* state;
  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    state = *(_ptr_attr_with_offset<FlowState*>(this->attr_offset(flow_stats_attr_id_), pkt));
    if (state == nullptr) {
      LOG(FATAL) << "split&enq: error (invalid non-flow packet)";
      bess::Packet::Free(pkt);
      continue;
    }

    auto& q_state = state->sw_q_state;
    if (q_state != nullptr) {
      if (q_state == &system_dump_q0_) {
        // Egress 7: drop (no sw_q)
        if (state->ingress_packet_count > state->egress_packet_count) {
          state->egress_packet_count += 1;
        }
        bess::Packet::Free(pkt);
        epoch_drop1_ += 1;
        continue;
      }
      if (q_state == &system_dump_q1_) {
        // Egress 8: drop (super flow)
        if (state->ingress_packet_count > state->egress_packet_count) {
          state->egress_packet_count += 1;
        }
        bess::Packet::Free(pkt);
        epoch_drop4_ += 1;
        continue;
      }

      if (q_state->idle_epoch_count == -1) {
        // Egress 9: drop (idle RCore)
        // Reset migration and drop |pkt|.
        state->sw_q_state = &system_dump_q1_;

        if (state->ingress_packet_count > state->egress_packet_count) {
          state->egress_packet_count += 1;
        }
        bess::Packet::Free(pkt);
        epoch_drop2_ += 1;
        continue;
      }

      // Egress 10: normal offloading
      // This flow is redirected only if an active RCore works on |sw_q|.
      if (state->ingress_packet_count > state->egress_packet_count) {
        state->egress_packet_count += 1;
      }
      q_state->sw_batch->add(pkt);
      continue;
    }

    if (state->enqueued_packet_count >= state->queued_packet_count) {
      if (state->ingress_packet_count > state->egress_packet_count) {
        state->egress_packet_count += 1;
      }
      bess::Packet::Free(pkt);
      continue;
    }

    state->enqueued_packet_count += 1;
    local_batch_->add(pkt);
  }

  // Just drop excessive packets when a software queue is full
  // Egress 11: drop (|local_queue_| overflow)
  BestEffortEnqueue(local_batch_, local_queue_);
  for (auto& sw_q_it : sw_q_) {
    sw_q_it.EnqueueBatch();
  }
}

void NFVCore::BestEffortEnqueue(bess::PacketBatch *batch, llring *q) {
  if (batch->cnt()) {
    FlowState *state = nullptr;
    int queued = llring_sp_enqueue_burst(q, (void **)batch->pkts(), batch->cnt());
    if (queued < 0) {
      queued = queued & (~RING_QUOT_EXCEED);
    }
    if (queued < batch->cnt()) {
      int to_drop = batch->cnt() - queued;
      for (int i = 0; i < to_drop; i++) {
        bess::Packet *pkt = batch->pkts()[queued + i];
        state = *(_ptr_attr_with_offset<FlowState*>(this->attr_offset(flow_stats_attr_id_), pkt));
        if (state->ingress_packet_count > state->egress_packet_count) {
          state->egress_packet_count += 1;
        }
        epoch_drop3_ += 1;
      }
      bess::Packet::Free(batch->pkts() + queued, to_drop);
    }
  }
}

bool NFVCore::ShortEpochProcess() {
  using bess::utils::all_core_stats_chan;

  uint32_t q_cnt = GetSoftwareQueueCount();
  if (q_cnt > large_queue_packet_thresh_) {
    // This |ncore| observes a large queue, and by default, it hopes that
    // the following short-term optimization can handle it with aux cores.
    // However, if it still sees a large queue in the next epoch, it tells
    // that an on-demand load-balancing is needed immediately ...
    num_epoch_with_large_queue_ += 1;
    if (num_epoch_with_large_queue_ > 1) {
      num_epoch_with_large_queue_ = 0;
      bess::ctrl::nfv_ctrl->NotifyCtrlLoadBalanceNow(core_id_);
    }
  }

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
  for (auto& sw_q_it : sw_q_) {
    if (sw_q_it.idle_epoch_count == -1) {
      continue;
    }
    if (sw_q_it.processed_packet_count == 0) {
      sw_q_it.idle_epoch_count += 1;
    } else {
      sw_q_it.idle_epoch_count = 0;
    }
    sw_q_it.assigned_packet_count = llring_count(sw_q_it.sw_q);
  }

  // Update |unoffload_flows_|
  unoffload_flows_.clear();

  uint32_t total_pkt_cnt = 0;
  uint32_t pkt_cnt = 0;
  for (auto it = epoch_flow_cache_.begin(); it != epoch_flow_cache_.end(); ++it) {
    FlowState *state = *it;
    if (state != nullptr) {
      if (state->ingress_packet_count >= state->egress_packet_count) {
        state->queued_packet_count = state->ingress_packet_count - state->egress_packet_count;
      } else {
        // LOG(ERROR) << "short-term: error. ig=" << state->ingress_packet_count << ", eg=" << state->egress_packet_count;
        state->queued_packet_count = 0;
      }
      // Reset so that the flow can be recorded in the next short epoch
      state->enqueued_packet_count = 0;
      state->short_epoch_packet_count = 0;

      total_pkt_cnt += state->queued_packet_count;
      if (state->sw_q_state != nullptr) {
        // Skip flows that have been assigned to migrate to RCores
        continue;
      }

      unoffload_flows_.emplace(state);
      pkt_cnt += state->queued_packet_count;
    } else {
      LOG(FATAL) << "short-term: error (impossible non-flow packet)";
    }
  }

  // Greedy assignment: first-fit
  uint32_t local_assigned = 0;
  uint32_t local_large_flow = 0;

  for (auto it = unoffload_flows_.begin(); it != unoffload_flows_.end(); ++it) {
    FlowState *state = *it;
    uint32_t task_size = state->queued_packet_count;

    if (task_size <= epoch_packet_thresh_) {
      if (local_assigned + task_size < epoch_packet_thresh_) {
        local_assigned += task_size;
      } else {
        bool assigned = false;
        for (auto& sw_q_it : sw_q_) {
          if (sw_q_it.QLenAfterAssignment() + task_size < epoch_packet_thresh_) {
            state->sw_q_state = &sw_q_it;
            sw_q_it.assigned_packet_count += task_size;
            assigned = true;
            break;
          }
        }
        if (!assigned) {
          // Existing software queues cannot hold this flow. Need more queues
          state->sw_q_state = &system_dump_q0_;
        }
      }
    } else {
      // This flow cannot be handled by only 1 core.
      local_large_flow += task_size;
      state->sw_q_state = &system_dump_q1_;
    }
  }
  // Debug log
  if (false && pkt_cnt > 0) {
    LOG(INFO) << "short-term: core" << core_id_ << ", tct=" << total_pkt_cnt << ", ct=" << pkt_cnt << ", lf=" << local_large_flow
              << ", d1=" << epoch_drop1_ << ", d2=" << epoch_drop2_ << ", d3=" << epoch_drop3_ << ", d4=" << epoch_drop4_;
  }

  // Notify reserved cores to do the work.
  int ret;
  for (auto& sw_q_it : sw_q_) {
    if (sw_q_it.idle_epoch_count == -1) { // inactive
      if (sw_q_it.assigned_packet_count > 0) { // got things to do
        ret = bess::ctrl::NFVCtrlNotifyRCoreToWork(core_id_, sw_q_it.sw_q_id);
        if (ret != 0) {
          LOG(ERROR) << "S error: " << ret << "; core: " << core_id_ << "; q: " << sw_q_it.sw_q_id;
        }
        sw_q_it.idle_epoch_count = 0;
      }
    } else { // |idle_epoch_count| >= 0; active
      if (sw_q_it.idle_epoch_count == 100) { // idle for a while
        ret = bess::ctrl::NFVCtrlNotifyRCoreToRest(core_id_, sw_q_it.sw_q_id);
        if (ret != 0) {
          LOG(ERROR) << "E error: " << ret << "; core: " << core_id_ << "; q: " << sw_q_it.sw_q_id;
        }
        sw_q_it.idle_epoch_count = -1;
      }
    }
    sw_q_it.processed_packet_count = 0;
  }

  // Clear
  CoreStats* stats_ptr = nullptr;
  while (all_core_stats_chan[core_id_]->Size()) {
    all_core_stats_chan[core_id_]->Pop(stats_ptr);
    delete (stats_ptr);
    stats_ptr = nullptr;
  }

  epoch_flow_cache_.clear();
  epoch_packet_arrival_ = 0;
  epoch_packet_processed_ = 0;
  epoch_drop1_ = 0;
  epoch_drop2_ = 0;
  epoch_drop3_ = 0;
  epoch_drop4_ = 0;
  return true;
}
