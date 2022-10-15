#ifndef BESS_MODULES_NFV_CTRL_H_
#define BESS_MODULES_NFV_CTRL_H_

#include <shared_mutex>

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../drivers/pmd.h"
#include "../utils/cpu_core.h"
#include "../utils/lock_less_queue.h"

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
  std::vector<int> RequestNSwQ(cpu_core_t core_id, int n);
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

  inline void AddQueue(struct llring* q) {
    llring_mp_enqueue(to_add_queue_, (void*)q);
  }
  inline void RemoveQueue(struct llring* q) {
    llring_mp_enqueue(to_remove_queue_, (void*)q);
  }

  struct task_result RunTask(Context *ctx, bess::PacketBatch *batch, void *arg) override;
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  // This function runs a heurisics algorithm to re-group RSS buckets
  // to the minimal # of normal cores according to the long-term NF
  // performance profile. It returns the # of moves for rebalancing
  // RSS buckets. 0 if nothing will change.
  uint32_t LongEpochProcess();

  // This function runs a heurisics algorithm to split RSS buckets
  // assigned to a core into two portions. One is kept locally. The
  // other one is migrated to the core with the min load on the worker.
  uint32_t OnDemandLongEpochProcess(u_int16_t core_id);

  // Send the current worker's info via a raw packet.
  void SendWorkerInfo();

  // This function can be called by NFVCore and NFVRCore when
  // they decide that an immediate load rebalancing is required.
  void NotifyCtrlLoadBalanceNow(uint16_t core_id);

  CommandResponse CommandGetSummary(const bess::pb::EmptyArg &arg);

  uint16_t GetCurrActiveCoreCount() {
    return rte_atomic16_read(&curr_active_core_count_);
  }

 private:
  // Return the max packet rate under flow count |fc| given the input NF profile.
  double GetMaxPktRateFromLongTermProfile(double fc);
  // LongTermOptimzation adjusts the system for long term changes. It makes sure
  // that no cores are violating p50 SLO. It also reduces resource consumption by
  // packing flows tightly and freeing up CPU cores.
  std::map<uint16_t, uint16_t> LongTermOptimization(
      const std::vector<double>& per_bucket_pkt_rate,
      const std::vector<double>& per_bucket_flow_count);

  std::map<uint16_t, uint16_t> OnDemandLongTermOptimization(
      uint16_t core_id,
      const std::vector<double>& per_bucket_pkt_rate,
      const std::vector<double>& per_bucket_flow_count);

  // Apply first-fit to find the best core for the set of RSS buckets to be migrated
  std::map<uint16_t, uint16_t> FindMoves(
      std::vector<double>& per_core_pkt_rate,
      std::vector<double>& per_core_flow_count,
      const std::vector<double>& per_bucket_pkt_rate,
      const std::vector<double>& per_bucket_flow_count,
      std::vector<uint16_t>& to_move_cores);

  uint64_t long_epoch_period_ns_;
  uint64_t last_long_epoch_end_ns_;
  uint64_t slo_p50_ = 200000000; // Current target is 200 ms

  int worker_id_;

  // For each normal CPU core, the set of assigned RSS buckets
  std::map<uint16_t, std::vector<uint16_t>> core_bucket_mapping_;

  // For updating RSS bucket assignment
  PMDPort *port_;
  queue_t qid_;
  bess::PacketBatch* local_batch_;

  // Normal cores and reserved cores
  uint16_t total_core_count_;
  uint16_t active_core_count_; // Updated during the algorithm

  rte_atomic16_t curr_active_core_count_; // Updated after the algorithm
  uint32_t curr_packet_rate_; // Updated during/after the algorithm

  be32_t monitor_src_ip_;
  be32_t monitor_dst_ip_;

  // The lock for maintaining a pool of software queues
  mutable std::mutex sw_q_mtx_;

  // A vector of software queues that cannot be assigned to a reserved core
  std::vector<struct llring*> to_dump_sw_q_;
  struct llring *to_add_queue_;
  struct llring *to_remove_queue_;

  uint64_t curr_ts_ns_;

  // If true, |this| normal core stops pulling packets from its NIC queue
  rte_atomic16_t disabled_;
  rte_atomic16_t mark_to_disable_;

  // Set by |NFVCore| and |NFVRCore| when a persistent traffic burst is
  // observed. |this| module will run a long-term optimization to rebalance
  // traffic loads across cores now. However, it should still respect the
  // NIC's hardware limitation: one cannot reprogram the NIC forwarding
  // table rule within ~5 ms (according to our measurement results).
  rte_atomic16_t is_rebalancing_load_now_;
};

#endif // BESS_MODULES_NFV_CTRL_H_