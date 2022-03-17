#ifndef BESS_MODULES_NFV_CTRL_H_
#define BESS_MODULES_NFV_CTRL_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"

#include "../utils/sys_measure.h"

using bess::utils::WorkerCore;

class NFVCtrl final : public Module {
 public:
  static const Commands cmds;
  static const gate_idx_t kNumIGates = 0;
  static const gate_idx_t kNumOGates = 0;

  NFVCtrl() : Module() { is_task_ = true; }

  CommandResponse Init(const bess::pb::NFVCtrlArg &arg);
  void DeInit() override;

  uint64_t RequestSwQ(int core_id, int n);

  struct task_result RunTask(Context *ctx, bess::PacketBatch *batch, void *arg) override;
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse CommandGetSummary(const bess::pb::EmptyArg &arg);

 private:
  // All available per-core packet queues in a cluster
  std::vector<WorkerCore> cpu_cores_;
  int total_core_count_ = 0;

  uint64_t curr_ts_ns_;
};

#endif // BESS_MODULES_NFV_CTRL_H_
