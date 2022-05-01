#ifndef BESS_MODULES_NFV_CTRL_H_
#define BESS_MODULES_NFV_CTRL_H_

#include <shared_mutex>

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../drivers/pmd.h"
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

  void InitPMD(PMDPort* port);

  // Returns |n| (idle) software queue's index as a bitmask.
  // Once assigned, the software queue is uniquely accessed by NFVCore (the caller).
  uint64_t RequestNSwQ(cpu_core_t core_id, int n);
  // Returns the software queue's index.
  int RequestSwQ(cpu_core_t core_id);

  // Releases many software queues back to the pool.
  void ReleaseNSwQ(cpu_core_t core_id, uint64_t q_mask);
  // Releases a software queue back to NFVCtrl.
  void ReleaseSwQ(int q_id);

  // For following functions:
  // 0: successful
  // 1: wrong core_id
  // 2: wrong q_id
  // 3: no idle RCore

  // Finds an idle NFVRCore to work on sw_q |q_id|.
  int NotifyRCoreToWork(cpu_core_t core_id, int q_id);
  // Notifies the NFVRCore to stop working on sw_q |q_id|.
  int NotifyRCoreToRest(cpu_core_t core_id, int q_id);

  struct task_result RunTask(Context *ctx, bess::PacketBatch *batch, void *arg) override;
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;
  void UpdateFlowAssignment();

  CommandResponse CommandGetSummary(const bess::pb::EmptyArg &arg);

 private:
  // LongTermOptimzation adjusts the system for long term changes. It makes sure
  // that no cores are violating p50 SLO. It also reduces resource consumption by
  // packing flows tightly and freeing up CPU cores.
  std::map<uint16_t, uint16_t> LongTermOptimization(const std::vector<double>& per_bucket_pkt_rate);

  // Apply first-fit to find the best core for the set of RSS buckets to be migrated
  std::map<uint16_t, uint16_t> FindMoves(std::vector<double>& per_core_pkt_rate, std::vector<uint16_t>& to_move_cores, const std::vector<double>& per_bucket_pkt_rate);

  uint64_t long_epoch_update_period_;
  uint64_t long_epoch_last_update_time_;
  uint64_t slo_p50_ = 200000000; // Current target is 200 ms

  // For each normal CPU core, the set of assigned RSS buckets
  std::map<uint16_t, std::vector<uint16_t>> core_bucket_mapping_;
  // packet rate threshold given the flow count. Values are found using offline profiling
  std::map<uint64_t, uint64_t> flow_count_pps_threshold_;

  // For updating RSS bucket assignment
  PMDPort *port_;
  // Normal cores and reserved cores
  std::vector<WorkerCore> cpu_cores_;
  uint16_t total_core_count_;
  uint16_t active_core_count_;

  // The lock for maintaining a pool of software queues
  mutable std::mutex sw_q_mtx_;

  uint64_t curr_ts_ns_;
};

#endif // BESS_MODULES_NFV_CTRL_H_
