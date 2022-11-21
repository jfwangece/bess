#include <nfv_ctrl_msg.h>
#include <metron_core.h>

CommandResponse MetronCore::Init(const bess::pb::MetronCoreArg& arg) {
  task_id_t tid;
  tid = RegisterTask(nullptr);
  if (tid == INVALID_TASK_ID) {
    return CommandFailure(ENOMEM, "Task creation failed");
  }

  core_id_ = 0;
  if (arg.core_id() > 0) {
    core_id_ = arg.core_id();
  }

  local_queue_ = bess::ctrl::local_mc_q[core_id_];
  return CommandSuccess();
}

void MetronCore::DeInit() {
  local_queue_ = nullptr;
  return;
}

// Get a batch from the 'NIC' queue and send it to downstream
struct task_result MetronCore::RunTask(Context *ctx, bess::PacketBatch *batch,
                                     void *) {
  if (local_queue_ == nullptr) {
    return {.block = false, .packets = 0, .bits = 0};
  }

  uint32_t cnt = llring_sc_dequeue_burst(local_queue_, (void **)batch->pkts(), 32);
  if (cnt == 0) {
    return {.block = false, .packets = 0, .bits = 0};
  }

  batch->set_cnt(cnt);
  uint64_t total_bytes = 0;
  for (uint32_t i = 0; i < cnt; i++) {
    total_bytes += batch->pkts()[i]->total_len();
  }

  RunNextModule(ctx, batch);

  return {.block = false,
          .packets = cnt,
          .bits = (total_bytes + cnt * 24) * 8};
}

void MetronCore::ProcessBatch(Context *, bess::PacketBatch *batch) {
  int queued =
      llring_mp_enqueue_burst(local_queue_, (void **)batch->pkts(), batch->cnt());
  if (queued < batch->cnt()) {
    int to_drop = batch->cnt() - queued;
    bess::Packet::Free(batch->pkts() + queued, to_drop);
  }
}

ADD_MODULE(MetronCore, "mcore",
           "A CPU core that pulls packets from |local_mc_q|.")
