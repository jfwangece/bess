#include "nfv_core.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/udp.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;
using bess::utils::Udp;

namespace {
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
} // namespace

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
    for (auto& sw_q_it : sw_q_) {
      if (sw_q_it.idle_epoch_count == -1) {
        continue;
      }
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
          if (!assigned) {
            // Existing software queues cannot hold this flow. Need more queues
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
      if (sw_q_it.idle_epoch_count == -1) { // inactive
        if (sw_q_it.assigned_packet_count > 0) { // got things to do
          ret = bess::ctrl::NFVCtrlNotifyRCoreToWork(core_id_, sw_q_it.sw_q_id);
          if (ret != 0) {
            LOG(ERROR) << "S " << ret;
          }
          sw_q_it.idle_epoch_count = 0;
        }
      } else { // |idle_epoch_count| >= 0; active
        if (sw_q_it.idle_epoch_count == 100) { // idle for a while
          ret = bess::ctrl::NFVCtrlNotifyRCoreToRest(core_id_, sw_q_it.sw_q_id);
          if (ret != 0) {
            LOG(ERROR) << "E " << ret;
          }
          sw_q_it.idle_epoch_count = -1;
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
    }

    epoch_flow_cache_.clear();
    epoch_packet_arrival_ = 0;
    epoch_packet_processed_ = 0;
    return true;
  }

  return false;
}
