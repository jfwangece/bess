#include <nfv_ctrl_msg.h>
#include <metron_core.h>

#include "../utils/packet_tag.h"

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

  // Init
  if (bess::ctrl::metron_cores[core_id_] == nullptr) {
    bess::ctrl::metron_cores[core_id_] = this;
  }

  // Quadrant measurements
  next_packet_delay_idx = 0;
  for (int i = 0; i < MostRecentPacketDelayCount; i++) {
    most_recent_packet_delays_[i] = 0;
  }
  max_packet_delay_ = 0;

  last_short_epoch_end_ns_ = tsc_to_ns(rdtsc());
  is_active_ = false;
  idle_epochs_ = 0;
  epoch_packet_count_ = 0;

  rte_atomic64_set(&sum_core_time_ns_, 0);
  rte_atomic16_set(&disabled_, 0);

  return CommandSuccess();
}

void MetronCore::DeInit() {
  local_queue_ = nullptr;
  rte_atomic16_set(&disabled_, 0);
  while (rte_atomic16_read(&disabled_) != 2) {
    usleep(100000);
  }
}

// Get a batch from the 'NIC' queue and send it to downstream
struct task_result MetronCore::RunTask(Context *ctx, bess::PacketBatch *batch,
                                     void *) {
  if (local_queue_ == nullptr) {
    LOG(INFO) << "metron: core " << core_id_ << " local_mc_q is not ready";
    return {.block = false, .packets = 0, .bits = 0};
  }

  if (rte_atomic16_read(&disabled_) == 1) {
    rte_atomic16_inc(&disabled_);
    return {.block = false, .packets = 0, .bits = 0};
  }

  // CPU core usage accounting
  uint64_t now = tsc_to_ns(rdtsc());
  if (now - last_short_epoch_end_ns_ >= 1000000) {
    if (epoch_packet_count_ < 100) {
      if (is_active_) {
        idle_epochs_ += 1;
        if (idle_epochs_ >= 500) {
          is_active_ = false;
        }
      }
    } else {
      is_active_ = true;
      idle_epochs_ = 0;
    }
    if (is_active_) {
      uint64_t core_diff = now - last_short_epoch_end_ns_;
      rte_atomic64_add(&sum_core_time_ns_, core_diff);
    }

    // Reset
    epoch_packet_count_ = 0;
    last_short_epoch_end_ns_ = tsc_to_ns(rdtsc());
  }

  uint32_t cnt = llring_sc_dequeue_burst(local_queue_, (void **)batch->pkts(), 32);
  if (cnt == 0) {
    return {.block = false, .packets = 0, .bits = 0};
  }
  epoch_packet_count_ += cnt;

  batch->set_cnt(cnt);
  uint64_t total_bytes = 0;
  uint64_t enqueue_ts = 0;
  for (uint32_t i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    total_bytes += pkt->total_len();

    // Quadrant gets the per-batch queueing delay
    if (i == cnt - 1) {
      bess::utils::GetUint64(pkt, WorkerDelayTsTagOffset, &enqueue_ts);
      bess::utils::TagUint64(pkt, WorkerDelayTsTagOffset, max_packet_delay_);

      most_recent_packet_delays_[next_packet_delay_idx] = tsc_to_ns(rdtsc()) - enqueue_ts;
      next_packet_delay_idx = (next_packet_delay_idx + 1) % MostRecentPacketDelayCount;
      if (next_packet_delay_idx == MostRecentPacketDelayCount - 1) {
        max_packet_delay_ = 0;
        for (int j = 0; j < MostRecentPacketDelayCount; j++) {
          if (max_packet_delay_ < most_recent_packet_delays_[j]) {
            max_packet_delay_ = most_recent_packet_delays_[j];
          }
        }
      }
    }
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

uint64_t MetronCore::GetSumCoreTime() {
  return rte_atomic64_read(&sum_core_time_ns_);
}

ADD_MODULE(MetronCore, "mcore",
           "A CPU core that pulls packets from |local_mc_q|.")
