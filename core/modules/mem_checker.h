#ifndef BESS_MODULES_MEM_CHECKER_H_
#define BESS_MODULES_MEM_CHECKER_H_

#include <vector>
#include <string>

#include "../module.h"
#include "../utils/mcslock.h"

class MemChecker final : public Module {
public:
  MemChecker() : Module() {
    max_allowed_workers_ = Worker::kMaxWorkers;
    total_packets_cnt_ = 0;
    invalid_packts_cnt_ = 0;
  }

  static const Commands cmds;

  static const gate_idx_t kNumIGates = MAX_GATES;

  CommandResponse Init(const bess::pb::MemCheckerArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse CommandGetSummary(const bess::pb::EmptyArg &);

private:
  // where to find the tag
  size_t offset1_ = 0;
  size_t offset2_ = 0;

  uint64_t total_packets_cnt_ = 0;
  uint64_t invalid_packts_cnt_ = 0;

  mcslock lock_;
};

#endif  // BESS_MODULES_MEM_CHECKER_H_
