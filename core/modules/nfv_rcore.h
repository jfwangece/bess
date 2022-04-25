#ifndef BESS_MODULES_NFV_RCORE_H_
#define BESS_MODULES_NFV_RCORE_H_

#include "nfv_ctrl_msg.h"

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../port.h"
#include "../utils/cpu_core.h"
#include "../utils/flow.h"
#include "../utils/ip.h"
#include "../utils/sys_measure.h"

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
  // |NFVRCore| will stop working on |q| when the next round starts
  inline void RemoveQueue(struct llring* q) {
    llring_mp_enqueue(to_remove_queue_, (void*)q);
  }

 private:
  cpu_core_t core_id_;
  WorkerCore core_;

  rte_atomic16_t is_in_use_;
  rte_atomic16_t mark_be_disabled_;
  rte_atomic16_t disabled_;

  struct llring *to_add_queue_;
  struct llring *to_remove_queue_;

  // Set by NFVCtrl
  struct llring* sw_q_;
  int burst_;
};

#endif // BESS_MODULES_NFV_RCORE_H_
