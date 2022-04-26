#ifndef BESS_MODULES_NFV_CORE_H_
#define BESS_MODULES_NFV_CORE_H_

#include "nfv_ctrl_msg.h"

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../port.h"
#include "../utils/cpu_core.h"
#include "../utils/flow.h"
#include "../utils/ip.h"
#include "../utils/sys_measure.h"

using bess::utils::Flow;
using bess::utils::FlowHash;
using bess::utils::FlowRoutingRule;
using bess::utils::CoreStats;
using bess::utils::WorkerCore;

// Assumption:
// if |active_flow_count| increases, |packet_count| will decrease
// Then, the admission process can be a packing problem.

// The assignment state for each software queue.
// |sw_q_id|: the global software queue index seen by NFVCtrl.
// |sw_q|: the (borrowed) software queue's pointer;
// |assigned_packet_count|: the number of packets to be enqueued;
// |processed_packet_count|: the number of packets seen by the queue;
// |idle_epoch_count|: the number of epoches with no packet arrivals;
struct SoftwareQueueState {
  SoftwareQueueState(int qid) : sw_q_id(qid) {
    sw_q = bess::ctrl::sw_q[qid];
    idle_epoch_count = 0;
    assigned_packet_count = 0; processed_packet_count = 0;
  }

  uint32_t QLenAfterAssignment() { return assigned_packet_count; }

  inline void EnqueueBatch() {
    if (sw_batch->cnt() == 0) {
      return;
    }
    processed_packet_count += sw_batch->cnt();
    int queued = llring_sp_enqueue_burst(sw_q, (void**)sw_batch->pkts(), sw_batch->cnt());
    if (queued < 0) {
      queued = queued & (~RING_QUOT_EXCEED);
    }
    if (queued < sw_batch->cnt()) {
      int to_drop = sw_batch->cnt() - queued;
      bess::Packet::Free(sw_batch->pkts() + queued, to_drop);
    }
  }

  struct llring* sw_q;
  bess::PacketBatch* sw_batch;
  int sw_q_id;
  int idle_epoch_count;
  uint32_t assigned_packet_count;
  uint32_t processed_packet_count;
};

struct FlowState {
  FlowState() {
    ingress_packet_count = egress_packet_count = queued_packet_count = 0;
    short_epoch_packet_count = 0;
    sw_q_state = nullptr;
  }

  uint32_t ingress_packet_count; // packet counter at ingress
  uint32_t short_epoch_packet_count; // short-term epoch packet counter
  uint32_t egress_packet_count; // packet counter at egress
  uint32_t queued_packet_count; // packet count in the system
  SoftwareQueueState *sw_q_state; // |this| flow sent to software queue w/ valid |sw_q_state|
};

class NFVCore final : public Module {
 public:
  static const Commands cmds;

  NFVCore() : Module(), local_queue_(0), burst_(32), size_(2048) {
    max_allowed_workers_ = 1;
  }

  CommandResponse Init(const bess::pb::NFVCoreArg &arg);
  void DeInit() override;

  struct task_result RunTask(Context *ctx, bess::PacketBatch *batch, void *arg);
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  // Check if a new short-term epoch has started.
  // If yes, check the remaining packet queue, and split traffic
  // if it will lead to SLO violations.
  // Returns true if a new epoch started.
  bool ShortEpochProcess();

  // Work on all flows in |unoffload_flows_|.
  // Decide the number of additional software queues and
  // assign flows to them.
  int PackFlowsToSoftwareQueues();

  // OnFetch:
  // - Add the per-flow state pointer to each packet's metadata.
  // All following updates will use this pointer instead of
  // computing the flow's hash.
  // - Update epoch and per-flow packet arrivals, flow arrivals
  void UpdateStatsOnFetchBatch(bess::PacketBatch *batch);

  // PreProcess:
  // - Update epoch packet processed, flow processed
  void UpdateStatsPreProcessBatch(bess::PacketBatch *batch);

  // PostProcess:
  // - Update epoch latency statistics
  void UpdateStatsPostProcessBatch(bess::PacketBatch *batch);

  std::string GetDesc() const override;

  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);
  CommandResponse CommandSetBurst(const bess::pb::NFVCoreCommandSetBurstArg &arg);

 private:
  int Resize(int slots);

  cpu_core_t core_id_;
  WorkerCore core_;

  // NIC queue (port, qid)
  Port *port_;
  queue_t qid_;

  // Software queue that holds packets
  struct llring *local_queue_;
  bess::PacketBatch *local_batch_;
  int burst_;
  uint64_t size_;

  // Software queues borrowed from NFVCtrl
  uint64_t sw_q_mask_;
  std::vector<SoftwareQueueState> sw_q_;
  std::unordered_map<Flow, int, FlowHash> flow_to_sw_q_;
  std::unordered_map<Flow, FlowState*, FlowHash> unoffload_flows_;

  // Metadata field ID
  int flow_stats_attr_id_; // for maintaining per-flow stats

  // Time-related
  uint64_t curr_ts_ns_;

  // Per-core admission control to avoid latency SLO violations
  // Based on our design, it approximates the NF profile curve
  uint32_t epoch_packet_thresh_;
  uint32_t epoch_flow_thresh_;

  // Max number of new flows processed in a epoch
  uint32_t epoch_packet_arrival_;
  uint32_t epoch_packet_processed_;
  uint32_t epoch_packet_queued_;

  // For recording active flows in an epoch
  std::unordered_map<Flow, FlowState*, FlowHash> epoch_flow_cache_;
  // For maintaining (per-core) FlowState structs
  std::unordered_map<Flow, FlowState*, FlowHash> per_flow_states_;
};

#endif // BESS_MODULES_NFV_CORE_H_
