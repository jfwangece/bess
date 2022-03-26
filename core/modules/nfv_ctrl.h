#ifndef BESS_MODULES_NFV_CTRL_H_
#define BESS_MODULES_NFV_CTRL_H_

#include <shared_mutex>

#include "../module.h"
#include "../pb/module_msg.pb.h"

#include "../utils/cpu_core.h"

using bess::utils::WorkerCore;

class NFVCtrl final : public Module {
 public:
  static const Commands cmds;
  static const gate_idx_t kNumIGates = 0;
  static const gate_idx_t kNumOGates = 0;

  NFVCtrl() : Module() { is_task_ = true; }

  CommandResponse Init(const bess::pb::NFVCtrlArg &arg);
  void DeInit() override;

  // Returns |n| (idle) software queue's index as a bitmask.
  // Once assigned, the software queue is uniquely accessed by NFVCore (the caller).
  uint64_t RequestNSwQ(cpu_core_t core_id, int n);
  // Returns the software queue's index.
  int RequestSwQ(cpu_core_t core_id);
  // Releases a software queue back to NFVCtrl.
  void ReleaseSwQ(int q_id);

  struct task_result RunTask(Context *ctx, bess::PacketBatch *batch, void *arg) override;
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse CommandGetSummary(const bess::pb::EmptyArg &arg);

 private:
  // All available per-core packet queues in a cluster
  std::vector<WorkerCore> cpu_cores_;
  int total_core_count_ = 0;

  // The lock for maintaining a pool of software queues
  mutable std::shared_mutex sw_q_mtx_;

  uint64_t curr_ts_ns_;
};

#endif // BESS_MODULES_NFV_CTRL_H_
