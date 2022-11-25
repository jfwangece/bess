#ifndef BESS_MODULES_METRON_CORE_H_
#define BESS_MODULES_METRON_CORE_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/lock_less_queue.h"

class MetronCore final : public Module {
 public:
  static const Commands cmds;

  MetronCore() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const bess::pb::MetronCoreArg& arg);
  void DeInit() override;

  CommandResponse CommandGetCoreTime(const bess::pb::EmptyArg &);

  struct task_result RunTask(Context *ctx, bess::PacketBatch *batch, void *arg);
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  uint64_t GetSumCoreTime();

 private:
  uint32_t core_id_;

  // Timestamps
  // CPU core usage is measured in epochs.
  uint64_t last_short_epoch_end_ns_;

  rte_atomic64_t sum_core_time_ns_;

  // Software queue that holds packets.
  struct llring *local_queue_;
};

#endif  // BESS_MODULES_METRON_CORE_H_
