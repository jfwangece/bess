#include <nfv_ctrl_msg.h>
#include <metron_core.h>

const Commands MetronCore::cmds = {
    {"get_core_time", "EmptyArg", MODULE_CMD_FUNC(&MetronCore::CommandGetCoreTime),
     Command::THREAD_SAFE},
};

CommandResponse MetronCore::CommandGetCoreTime(const bess::pb::EmptyArg &) {
  uint64_t sum = 0;
  for (int i = 0; i < bess::ctrl::ncore; i++) {
    if (bess::ctrl::metron_cores[i] != nullptr) {
      sum += bess::ctrl::metron_cores[i]->GetSumCoreTime();
    }
  }

  bess::pb::MetronCoreCommandGetCoreTimeResponse r;
  r.set_core_time(sum);
  return CommandSuccess(r);
}

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
  if (local_queue_ == nullptr) {
    LOG(INFO) << "metron: core " << core_id_ << " local_mc_q is not ready";
  }
  LOG(INFO) << "metron: core " << core_id_;

  // Reset
  rte_atomic64_set(&sum_core_time_ns_, 0);

  last_short_epoch_end_ns_ = tsc_to_ns(rdtsc());

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
    LOG(INFO) << "metron: core " << core_id_ << " local_mc_q is not ready";
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

  uint64_t now = tsc_to_ns(rdtsc());
  if (now - last_short_epoch_end_ns_ >= 1000000) {
    uint64_t core_diff = now - last_short_epoch_end_ns_;
    rte_atomic64_add(&sum_core_time_ns_, core_diff);
    last_short_epoch_end_ns_ = tsc_to_ns(rdtsc());
  }

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

uint64_t MetronCore::GetSumCoreTime() {
  return rte_atomic64_read(&sum_core_time_ns_);
}

ADD_MODULE(MetronCore, "mcore",
           "A CPU core that pulls packets from |local_mc_q|.")
