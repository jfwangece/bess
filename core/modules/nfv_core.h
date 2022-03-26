#ifndef BESS_MODULES_NFV_CORE_H_
#define BESS_MODULES_NFV_CORE_H_

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

class NFVCore final : public Module {
 public:
  static const Commands cmds;

  NFVCore() : Module(),
    queue_(),
    burst_(),
    size_() {
    max_allowed_workers_ = 1;
  }

  CommandResponse Init(const bess::pb::NFVCoreArg &arg);
  void DeInit() override;

  struct task_result RunTask(Context *ctx, bess::PacketBatch *batch, void *arg);
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  std::string GetDesc() const override;

  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);
  CommandResponse CommandSetBurst(const bess::pb::NFVCoreCommandSetBurstArg &arg);

  void UpdateEpochStats(bess::PacketBatch *batch);
  bool update_traffic_stats();

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

  // Time-related
  uint64_t curr_ts_ns_;

  // Max number of new flows processed in a epoch
  uint32_t epoch_packet_thresh_;
  uint32_t epoch_flow_thresh_;
  uint32_t epoch_packet_arrival_;
  uint32_t epoch_packet_processed_;
  uint32_t epoch_packet_queued_;

  // Flow cache
  std::unordered_map<Flow, bool, FlowHash> epoch_flow_cache_;
  std::unordered_map<Flow, uint32_t, FlowHash> per_flow_packet_counter_;
};

#endif // BESS_MODULES_NFV_CORE_H_
