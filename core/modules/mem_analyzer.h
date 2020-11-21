#ifndef BESS_MODULES_MEM_ANALYZER_H_
#define BESS_MODULES_MEM_ANALYZER_H_

#include <map>
#include <string>

#include "../module.h"
#include "../utils/mcslock.h"

class MemAnalyzer final : public Module {
public:
  struct PacketMem {
    uint64_t paddr;
    uint64_t vaddr;
    void* ptr;
  };

  struct MemzoneMem {
    uint64_t paddr;
    uint64_t vaddr;
    const struct rte_memzone* ptr;
  };

  MemAnalyzer() : Module() {
    max_allowed_workers_ = Worker::kMaxWorkers;
    paddr_to_packets_.clear();

    mcs_lock_init(&lock_);
  }

  static const Commands cmds;

  static const gate_idx_t kNumIGates = MAX_GATES;

  CommandResponse Init(const bess::pb::MemAnalyzerArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse CommandGetSummary(const bess::pb::EmptyArg &);

  std::string GetDesc() const override;

private:
  bool hack_mode_ = false;

  std::map<uint64_t, PacketMem> hack_packets_;

  std::map<uint64_t, PacketMem> paddr_to_packets_;

  std::map<uint64_t, MemzoneMem> paddr_to_memzones_;

  uint64_t total_paddr_cnt_ = 0;

  uint64_t total_memzone_cnt_ = 0;

  mcslock lock_;
};

#endif  // BESS_MODULES_MEM_ANALYZER_H_
