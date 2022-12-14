#include "nfv_rcore.h"

#include "../drivers/pmd.h"
#include "../port.h"

const Commands NFVRCore::cmds = {
  {"set_burst", "NFVRCoreCommandSetBurstArg", MODULE_CMD_FUNC(&NFVRCore::CommandSetBurst),
     Command::THREAD_SAFE},
};

namespace {
// uint64_t get_hw_timestamp_nic(bess::Packet *pkt) {
//   uint64_t nic_cycle = reinterpret_cast<rte_mbuf*>(pkt)->timestamp;
//   return nic_tsc_to_ns(nic_cycle);
// }
}

// NFVRCore member functions
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
  bess::ctrl::rcore_state[core_id_] = true; // ready for any new work

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
  if (core_id_ < bess::ctrl::ncore) {
    sw_q_ = bess::ctrl::local_boost_q[core_id_];
    LOG(INFO) << "rcore (core-boost): " << core_id_;
  } else if (core_id_ >= bess::ctrl::rcore) {
    sw_q_ = bess::ctrl::system_dump_q_;
    LOG(INFO) << "rcore (rcore-boost): " << core_id_;
  } else {
    LOG(INFO) << "rcore (normal): " << core_id_;
  }

  // Run!
  qid_ = -1;
  rte_atomic16_set(&sw_q_id_, -1);
  rte_atomic16_set(&disabled_, 0);
  return CommandSuccess();
}

void NFVRCore::DeInit() {
  // Mark to stop the pipeline and wait until the pipeline stops
  rte_atomic16_set(&disabled_, 1);
  while (rte_atomic16_read(&disabled_) == 2) { usleep(100000); }

  // Clean the software queue that is currently being processed
  qid_ = -1;
  rte_atomic16_set(&sw_q_id_, -1);
  sw_q_ = nullptr;

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

CommandResponse NFVRCore::CommandSetBurst(
    const bess::pb::NFVRCoreCommandSetBurstArg &arg) {
  if (arg.burst() > bess::PacketBatch::kMaxBurst) {
    return CommandFailure(EINVAL, "burst size must be [0,%zu]",
                          bess::PacketBatch::kMaxBurst);
  } else {
    burst_ = arg.burst();
    return CommandSuccess();
  }
}

struct task_result NFVRCore::RunTask(Context *ctx, bess::PacketBatch *batch, void *) {
  if (rte_atomic16_read(&disabled_) == 1) {
    rte_atomic16_set(&disabled_, 2);
    return {.block = false, .packets = 0, .bits = 0};
  }

  // // 1) check |remove|
  // if (llring_count(to_remove_queue_) == 1) {
  //   llring *q = nullptr;
  //   llring_sc_dequeue(to_remove_queue_, (void**)&q);
  //   if (q == sw_q_) {
  //     sw_q_ = nullptr;
  //     return {.block = false, .packets = 0, .bits = 0};
  //   }
  // }
  // // 2) check |add|
  // if (sw_q_ == nullptr) {
  //   if (llring_count(to_add_queue_) >= 1) {
  //     return {.block = false, .packets = 0, .bits = 0};
  //   }
  //   llring_sc_dequeue(to_add_queue_, (void**)&sw_q_);
  // }

  if (sw_q_ == nullptr) {
    // to add
    int16_t qid = rte_atomic16_read(&sw_q_id_);
    if (qid == -1) {
      return {.block = false, .packets = 0, .bits = 0};
    }
    // Hand-off to me
    bess::ctrl::sw_q_state[qid]->SetDownCoreID(core_id_);
    sw_q_ = bess::ctrl::sw_q[qid];
    rte_atomic16_set(&sw_q_id_, -1);
  } else {
    // to remove
    int16_t qid = rte_atomic16_read(&sw_q_id_);
    if (qid != -1) {
      if (qid > 200 && sw_q_ == bess::ctrl::sw_q[qid - 200]) {
        qid_ = qid - 200;
      }
      rte_atomic16_set(&sw_q_id_, -1);
    }
  }

  if (qid_ != -1) {
    if (llring_count(sw_q_) == 0) {
      // Hand-off to NFVCore
      bess::ctrl::sw_q_state[qid_]->SetDownCoreID(DEFAULT_INVALID_CORE_ID);
      qid_ = -1;
      sw_q_ = nullptr;
      bess::ctrl::rcore_state[core_id_] = true; // ready for any new work
      return {.block = false, .packets = 0, .bits = 0};
    }
  }

  // 3) then, |sw_q_| != nullptr; start the NF chain
  const int burst = ACCESS_ONCE(burst_);
  uint32_t cnt = llring_mc_dequeue_burst(sw_q_, (void **)batch->pkts(), burst);
  if (cnt == 0) {
    return {.block = false, .packets = 0, .bits = 0};
  }
  batch->set_cnt(cnt);

  uint64_t total_bytes = 0;
  // uint64_t curr_nic_ts_ns = nic_tsc_to_ns(nic_rdtsc());
  // uint64_t max_pkt_delay = 0;
  for (uint32_t i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    rte_prefetch0(pkt->head_data());
    total_bytes += pkt->total_len();
    // uint64_t pkt_ts_ns = get_hw_timestamp_nic(pkt);
    // if (curr_nic_ts_ns > pkt_ts_ns) {
    //   uint64_t pkt_delay = curr_nic_ts_ns - pkt_ts_ns;
    //   if (pkt_delay < max_pkt_delay) {
    //     max_pkt_delay = pkt_delay;
    //   }
    // }
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
