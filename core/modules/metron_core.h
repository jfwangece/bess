#ifndef BESS_MODULES_METRON_CORE_H_
#define BESS_MODULES_METRON_CORE_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/lock_less_queue.h"

class MetronCore final : public Module {
 public:
  MetronCore() : Module() { max_allowed_workers_ = 1; }

  CommandResponse Init(const bess::pb::MetronCoreArg& arg);
  void DeInit() override;

  struct task_result RunTask(Context *ctx, bess::PacketBatch *batch, void *arg);
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

 private:
  uint32_t core_id_;

  // Software queue that holds packets.
  struct llring *local_queue_;
};

#endif  // BESS_MODULES_METRON_CORE_H_
