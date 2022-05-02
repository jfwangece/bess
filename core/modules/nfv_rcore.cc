#include "nfv_rcore.h"

const Commands NFVRCore::cmds = {
};

// NFVCore member functions
CommandResponse NFVRCore::Init(const bess::pb::NFVRCoreArg &arg) {
  task_id_t tid = RegisterTask((void *)(uintptr_t)0);
  if (tid == INVALID_TASK_ID) {
    return CommandFailure(ENOMEM, "Task creation failed");
  }

  // Configure the target CPU core ID
  core_id_ = 0;
  if (arg.core_id() > 0) {
    core_id_ = arg.core_id();
  }
  core_.core_id = core_id_;

  burst_ = bess::PacketBatch::kMaxBurst;

  // Init
  bess::ctrl::nfv_rcores[core_id_] = this;
  bess::ctrl::rcore_state[core_id_] = true;

  size_t kQSize = 64;
  int bytes = llring_bytes_with_slots(kQSize);
  to_add_queue_ = reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));
  if (to_add_queue_) {
    llring_init(to_add_queue_, kQSize, 0, 1);
  }
  to_remove_queue_ = reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));
  if (to_remove_queue_) {
    llring_init(to_remove_queue_, kQSize, 0, 1);
  }
  sw_q_ = nullptr;

  // Run!
  rte_atomic16_set(&mark_to_disable_, 0);
  rte_atomic16_set(&disabled_, 0);
  return CommandSuccess();
}

void NFVRCore::DeInit() {
  // Mark to stop the pipeline and wait until the pipeline stops
  rte_atomic16_set(&mark_to_disable_, 1);
  while (rte_atomic16_read(&disabled_) == 0) { usleep(100000); }

  // Clean the software queue that is currently being processed
  if (sw_q_) {
    sw_q_ = nullptr;
  }

  // Clean any queues that are pending
  if (to_add_queue_) {
    while (llring_sc_dequeue(to_add_queue_, (void **)&sw_q_) == 0) { continue; }
    std::free(to_add_queue_);
    to_add_queue_ = nullptr;
  }

  if (to_remove_queue_) {
    while (llring_sc_dequeue(to_remove_queue_, (void **)&sw_q_) == 0) { continue; }
    std::free(to_remove_queue_);
    to_remove_queue_ = nullptr;
  }
}

struct task_result NFVRCore::RunTask(Context *ctx, bess::PacketBatch *batch,
                                     void *) {
  if (rte_atomic16_read(&mark_to_disable_) == 1) {
    rte_atomic16_set(&disabled_, 1);
    return {.block = false, .packets = 0, .bits = 0};
  }
  if (rte_atomic16_read(&disabled_) == 1) {
    return {.block = false, .packets = 0, .bits = 0};
  }

  // 1) check |remove|
  if (llring_count(to_remove_queue_) == 1) {
    llring *q = nullptr;
    llring_sc_dequeue(to_remove_queue_, (void**)&q);
    if (q == sw_q_) {
      sw_q_ = nullptr;
      return {.block = false, .packets = 0, .bits = 0};
    }
  }

  // 2) check |add|
  if (sw_q_ == nullptr) {
    if (llring_count(to_add_queue_) != 1) {
      return {.block = false, .packets = 0, .bits = 0};
    }
    llring_sc_dequeue(to_add_queue_, (void**)&sw_q_);
  }

  // 3) then, |sw_q_| != nullptr; start the NF chain
  const int burst = ACCESS_ONCE(burst_);
  uint32_t cnt = llring_sc_dequeue_burst(sw_q_, (void **)batch->pkts(), burst);
  if (cnt == 0) {
    return {.block = false, .packets = 0, .bits = 0};
  }
  batch->set_cnt(cnt);

  uint64_t total_bytes = 0;
  for (uint32_t i = 0; i < cnt; i++) {
    rte_prefetch0(batch->pkts()[i]->head_data());
    total_bytes += batch->pkts()[i]->total_len();
  }

  RunNextModule(ctx, batch);

  return {.block = false,
          .packets = cnt,
          .bits = (total_bytes + cnt * 24) * 8};
}

void NFVRCore::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  RunNextModule(ctx, batch);
}

ADD_MODULE(NFVRCore, "nfv_rcore", "It handles traffic burstiness at a reserved core")
