#ifndef BESS_MODULES_NFV_RCORE_H_
#define BESS_MODULES_NFV_RCORE_H_

#include "nfv_ctrl_msg.h"

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../port.h"
#include "../utils/cpu_core.h"
#include "../utils/lock_less_queue.h"

using bess::utils::WorkerCore;

// A reserved CPU core for processing temporary packet burst.
// Each NFVCore can split a large packet queue into many smaller
// queues. Each of these queues will then be handled by a NFVRCore.
class NFVRCore final : public Module {
 public:
  static const Commands cmds;

  NFVRCore() : Module(), burst_(32) {
    is_task_ = true; max_allowed_workers_ = 1;
  }

  CommandResponse Init(const bess::pb::NFVRCoreArg &arg);
  void DeInit() override;

  struct task_result RunTask(Context *ctx, bess::PacketBatch *batch, void *arg) override;
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  // |NFVRCore| will start working on |q| when the next round starts
  inline void AddQueue(struct llring* q) {
    llring_mp_enqueue(to_add_queue_, (void*)q);
  }
  inline void AddQueue(int16_t qid) {
    rte_atomic16_set(&sw_q_id_, qid);
  }

  // |NFVRCore| will stop working on |q| when the next round starts
  inline void RemoveQueue(struct llring* q) {
    llring_mp_enqueue(to_remove_queue_, (void*)q);
  }
  inline void RemoveQueue(int16_t qid) {
    rte_atomic16_set(&sw_q_id_, 200+qid);
  }

  CommandResponse CommandSetBurst(const bess::pb::NFVRCoreCommandSetBurstArg &arg);

 private:
  cpu_core_t core_id_;
  WorkerCore core_;

  // NFVCore -> NFVCtrl
  struct llring *to_add_queue_;
  struct llring *to_remove_queue_;
  rte_atomic16_t sw_q_id_;

  // Set by myself after reading |sw_q_id_|
  int16_t qid_;
  struct llring* sw_q_;
  int burst_;

  // If true, |this| normal core stops pulling packets from its NIC queue
  rte_atomic16_t disabled_;
};

#endif // BESS_MODULES_NFV_RCORE_H_
