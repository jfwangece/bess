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

struct FlowState {
  FlowState() {
    ingress_packet_count = 0;
    short_epoch_packet_count = 0;
    egress_packet_count = 0;
  }

  uint32_t ingress_packet_count; // packet counter at ingress
  uint32_t short_epoch_packet_count; // short-term epoch packet counter
  uint32_t egress_packet_count; // packet counter at egress
  uint32_t unused;
};

class NFVCore final : public Module {
 public:
  static const Commands cmds;

  NFVCore() : Module(), queue_(0), burst_(32), size_(2048) {
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
  struct llring *queue_;
  int burst_;
  uint64_t size_;

  // Software queues borrowed from NFVCtrl
  int sw_q_count;
  std::unordered_map<Flow, int, FlowHash> flow_to_sw_q_;
  struct llring* sw_q[DEFAULT_SWQ_COUNT];

  // Metadata field ID
  int flow_stats_attr_id_; // for maintaining per-flow stats

  // Time-related
  uint64_t curr_ts_ns_;

  // Max number of new flows processed in a epoch
  uint32_t epoch_packet_thresh_;
  uint32_t epoch_flow_thresh_;
  uint32_t epoch_packet_arrival_;
  uint32_t epoch_packet_processed_;
  uint32_t epoch_packet_queued_;

  // For recording active flows in an epoch
  std::unordered_map<Flow, FlowState*, FlowHash> epoch_flow_cache_;
  // For maintaining (per-core) FlowState structs
  std::unordered_map<Flow, FlowState*, FlowHash> per_flow_states_;
};

#endif // BESS_MODULES_NFV_CORE_H_
