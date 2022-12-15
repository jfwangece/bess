#ifndef BESS_MODULES_NFV_CORE_H_
#define BESS_MODULES_NFV_CORE_H_

#include "nfv_ctrl_msg.h"

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../port.h"
#include "../utils/cpu_core.h"
#include "../utils/cuckoo_map.h"
#include "../utils/flow.h"
#include "../utils/sys_measure.h"

#include <set>

using bess::utils::Flow;
using bess::utils::FlowHash;
using bess::utils::FlowRoutingRule;
using bess::utils::CoreStats;
using bess::utils::BucketStats;
using bess::ctrl::SoftwareQueueState;

// Assumption:
// if |active_flow_count| increases, |packet_count| will decrease
// Then, the admission process can be a packing problem.

struct FlowState {
  FlowState() {
    rss = 0;
    short_epoch_packet_count = 0;
    queued_packet_count = 0;
    enqueued_packet_count = 0;
    sw_q_state = nullptr;
  }

  Flow flow;
  uint32_t rss; // NIC's RSS-based hash for |flow|
  uint32_t short_epoch_packet_count; // short-term epoch packet counter
  uint32_t queued_packet_count; // packet count in the system
  uint32_t enqueued_packet_count; // packet count in the SplitAndEnqueue process
  SoftwareQueueState *sw_q_state; // |this| flow sent to software queue w/ valid |sw_q_state|
};

class NFVCore final : public Module {
 public:
  static const Commands cmds;

  NFVCore() : Module(), burst_(32) {
    local_q_ = nullptr;
    local_boost_q_ = nullptr;
    max_allowed_workers_ = 1;
  }

  CommandResponse Init(const bess::pb::NFVCoreArg &arg);
  void DeInit() override;

  struct task_result RunTask(Context *ctx, bess::PacketBatch *batch, void *arg);
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;
  CommandResponse CommandGetCoreTime(const bess::pb::EmptyArg &);

  uint64_t GetSumCoreTime();

  // Check if a new short-term epoch has started.
  // If yes, check the remaining packet queue, and split traffic
  // if it will lead to SLO violations.
  // Returns true if a new epoch started.
  bool ShortEpochProcess();

  // OnFetch:
  // - Add the per-flow state pointer to each packet's metadata.
  // All following updates will use this pointer instead of
  // computing the flow's hash.
  // - Update epoch and per-flow packet arrivals, flow arrivals
  void UpdateStatsOnFetchBatch(bess::PacketBatch *batch);

  // PreProcess:
  // - Update epoch packet processed, flow processed
  void UpdateStatsPreProcessBatch(bess::PacketBatch *batch);

  // Notify this core to upload per-bucket states
  void UpdateBucketStats();

  // EpochEndProcess:
  // - Scan all packets in |q| and split them to all software queues
  void SplitQToSwQ(llring* q);
  // - Split |batch| into |local_queue_| and other software queues
  void SplitAndEnqueue(bess::PacketBatch *batch);
  // - (sp) Enqueue all packets in |batch| to the software queue |q|
  inline void SpEnqueue(bess::PacketBatch *batch, llring *q) {
    if (batch->cnt()) {
      int queued = llring_sp_enqueue_burst(q, (void **)batch->pkts(), batch->cnt());
      if (queued < 0) {
        queued = queued & (~RING_QUOT_EXCEED);
      }
      if (queued < batch->cnt()) {
        int to_drop = batch->cnt() - queued;
        bess::Packet::Free(batch->pkts() + queued, to_drop);
      }
      batch->clear();
    }
  }
  // - (mp) Enqueue all packets in |batch| to the software queue |q|
  inline void MpEnqueue(bess::PacketBatch *batch, llring *q) {
    if (batch->cnt()) {
      int queued = llring_mp_enqueue_burst(q, (void **)batch->pkts(), batch->cnt());
      if (queued < 0) {
        queued = queued & (~RING_QUOT_EXCEED);
      }
      if (queued < batch->cnt()) {
        int to_drop = batch->cnt() - queued;
        bess::Packet::Free(batch->pkts() + queued, to_drop);
      }
      batch->clear();
    }
  }

  // std::string GetDesc() const override;
  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);
  CommandResponse CommandSetBurst(const bess::pb::NFVCoreCommandSetBurstArg &arg);

 private:
  // For fast insertion (with a constant-time worse case insertion).
  using HashTable = bess::utils::CuckooMap<Flow, FlowState*, FlowHash, Flow::EqualTo>;

  uint16_t core_id_;

  // NIC queue (port, qid)
  Port *port_;
  uint16_t port_id_;
  queue_t qid_;
  int burst_;

  // Software queue that holds packets
  struct llring *local_q_;
  struct llring *local_boost_q_;

  bess::PacketBatch *local_batch_;
  bess::PacketBatch *local_rboost_batch_;
  bess::PacketBatch *system_dump_batch_;
  bess::PacketBatch *split_enqueue_batch_;

  /// Software queues:
  // q0: for flows marked to be dropped (running out of sw queues);
  // q1: for flows marked to be sent to boost-mode rcores;
  SoftwareQueueState* rcore_booster_q_state_;
  SoftwareQueueState* system_dump_q_state_;

  // Software queues borrowed from NFVCtrl
  std::set<SoftwareQueueState*> active_sw_q_;
  std::set<SoftwareQueueState*> terminating_sw_q_;

  // Metadata field ID
  int flow_stats_attr_id_; // for maintaining per-flow stats

  // Time-related
  uint64_t curr_ts_ns_;
  // Short epoch: last timestamp, period, and current ID
  uint64_t last_short_epoch_end_ns_;
  uint64_t short_epoch_period_ns_;
  uint64_t last_boost_ts_ns_;
  uint32_t curr_epoch_id_;
  int max_idle_epoch_count_;

  // Core-related
  uint32_t curr_rcore_ = 0;
  rte_atomic64_t sum_core_time_ns_;

  // Per-core admission control to avoid latency SLO violations
  // Based on our design, it approximates the NF profile curve
  uint32_t epoch_packet_thresh_;
  uint32_t busy_pull_round_thresh_;
  uint32_t large_queue_packet_thresh_;

  // Max number of new flows processed in a epoch
  uint32_t epoch_packet_arrival_;
  uint32_t epoch_packet_processed_;
  uint32_t epoch_packet_queued_;

  // Number of consecutive short-term epochs with a large packet queue;
  // If |num_epoch_with_large_queue_| is large, |this| core should call
  // nfvctrl->NotifyCtrlLoadBalanceNow();
  uint32_t num_epoch_with_large_queue_;

  // For recording per-bucket packet and flow counts
  bool update_bucket_stats_;
  BucketStats local_bucket_stats_;

  // For recording active flows in an epoch
  std::set<FlowState*> epoch_flow_cache_;
  // For each epoch, the set of flows that are not migrated to aux cores
  std::set<FlowState*> unoffload_flows_;

  // For maintaining (per-core) FlowState structs
  HashTable per_flow_states_;

  // For debugging
  uint32_t epoch_drop1_;
  uint32_t epoch_drop2_;
  uint32_t epoch_drop3_;
  uint32_t epoch_drop4_;

  // Other threads can set |disabled_| to be 1 to stop this core.
  // Once set, this core will set |disabled_| to be 2 to notify others
  // that this core has stopped successfully.
  rte_atomic16_t disabled_;
};

#endif // BESS_MODULES_NFV_CORE_H_
