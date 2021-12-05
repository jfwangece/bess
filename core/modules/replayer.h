#ifndef BESS_MODULES_REPLAYER_H_
#define BESS_MODULES_REPLAYER_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"

class Replayer final : public Module {
 public:
  Replayer() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const bess::pb::ReplayerArg &arg);
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

 private:
  // The offset / attribute ID of the per-packet timestamp
  size_t offset_;
};

#endif // BESS_MODULES_REPLAYER_H_
