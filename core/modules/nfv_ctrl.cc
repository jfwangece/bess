#include "nfv_ctrl.h"
#include "nfv_ctrl_msg.h"
#include "nfv_core.h"
#include "nfv_rcore.h"
#include "nfv_monitor.h"

#include "../module_graph.h"

// The time interval for the long term optimization to run
#define LONG_TERM_UPDATE_PERIOD_NS 500000000
#define MIN_NIC_RSS_UPDATE_PERIOD_NS 5000000

namespace {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
void DumpSoftwareQueue(struct llring* q, bess::PacketBatch *batch) {
  uint32_t cnt = 0;
  batch->clear();
  while ((cnt = llring_sc_dequeue_burst(q,
                (void **)batch->pkts(), batch->kMaxBurst)) > 16) {
    bess::Packet::Free(batch->pkts(), cnt);
    batch->clear();
  }
}

void DumpOnceSoftwareQueue(struct llring* q, bess::PacketBatch *batch) {
  batch->clear();
  int cnt = llring_sc_dequeue_burst(q, (void **)batch->pkts(), batch->kMaxBurst);
  if (cnt) {
    bess::Packet::Free(batch->pkts(), cnt);
  }
  // LOG(INFO) << q << ", " << cnt << ", " << llring_count(q);
}
#pragma GCC diagnostic pop
} // namespace

/// NFVCtrl's own functions:

const Commands NFVCtrl::cmds = {
    {"get_summary", "EmptyArg", MODULE_CMD_FUNC(&NFVCtrl::CommandGetSummary),
     Command::THREAD_SAFE},
};

uint64_t NFVCtrl::RequestNSwQ(cpu_core_t core_id, int n) {
  uint64_t bitmask = 0ULL;
  if (core_id == DEFAULT_INVALID_CORE_ID) {
    return bitmask;
  }

  // Only one NFVCore can call the following session at a time.
  const std::lock_guard<std::mutex> lock(sw_q_mtx_);

  int assigned = 0;
  // Find a (idle) software queue
  for (int i = 0; (i < DEFAULT_SWQ_COUNT) && (assigned < n); i++) {
    if (bess::ctrl::sw_q_state[i]->up_core_id == DEFAULT_INVALID_CORE_ID) {
      assigned += 1;
      bess::ctrl::sw_q_state[i]->up_core_id = core_id;
      bitmask |= 1ULL << i;
    }
  }
  return bitmask;
}

int NFVCtrl::RequestSwQ(cpu_core_t core_id) {
  if (core_id == DEFAULT_INVALID_CORE_ID) {
    return DEFAULT_SWQ_COUNT;
  }

  // Only one NFVCore can call the following session at a time.
  const std::lock_guard<std::mutex> lock(sw_q_mtx_);

  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    if (bess::ctrl::sw_q_state[i]->up_core_id == DEFAULT_INVALID_CORE_ID) {
      bess::ctrl::sw_q_state[i]->up_core_id = core_id;
      return i;
    }
  }
  return DEFAULT_SWQ_COUNT;
}

void NFVCtrl::ReleaseNSwQ(cpu_core_t core_id, uint64_t q_mask) {
  const std::lock_guard<std::mutex> lock(sw_q_mtx_);

  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    uint64_t sw_q_idx = (1ULL << i) & q_mask;
    if (sw_q_idx != 0 && bess::ctrl::sw_q_state[i]->up_core_id == core_id) {
      bess::ctrl::sw_q_state[i]->up_core_id = DEFAULT_INVALID_CORE_ID;
    }
  }
}

void NFVCtrl::ReleaseSwQ(int q_id) {
  const std::lock_guard<std::mutex> lock(sw_q_mtx_);

  bess::ctrl::sw_q_state[q_id]->up_core_id = DEFAULT_INVALID_CORE_ID;
}

int NFVCtrl::NotifyRCoreToWork(cpu_core_t core_id, int q_id) {
  const std::lock_guard<std::mutex> lock(sw_q_mtx_);

  // Do not assign if sw_q |q_id| does not belong to NFVCore |core_id|
  if (bess::ctrl::sw_q_state[q_id]->up_core_id != core_id) {
    return 1;
  }
  // Do not assign if sw_q |q_id| has already been assigned
  if (bess::ctrl::sw_q_state[q_id]->down_core_id != DEFAULT_INVALID_CORE_ID) {
    return 2;
  }

  // Find an idle reserved core
  for (int i = 0; i < DEFAULT_INVALID_CORE_ID; i++) {
    if (bess::ctrl::nfv_rcores[i] == nullptr ||
        !bess::ctrl::rcore_state[i]) {
      continue;
    }

    // Success
    bess::ctrl::rcore_state[i] = false;
    bess::ctrl::nfv_rcores[i]->AddQueue(bess::ctrl::sw_q[q_id]);
    bess::ctrl::sw_q_state[q_id]->down_core_id = i;
    return 0;
  }

  // No RCores found. System Overloaded! Hand-off to NFVCtrl
  this->AddQueue(bess::ctrl::sw_q[q_id]);
  bess::ctrl::sw_q_state[q_id]->down_core_id = DEFAULT_NFVCTRL_CORE_ID;
  return 3;
}

int NFVCtrl::NotifyRCoreToRest(cpu_core_t core_id, int q_id) {
  const std::lock_guard<std::mutex> lock(sw_q_mtx_);

  // Do not change if sw_q |q_id| does not belong to NFVCore |core_id|
  if (bess::ctrl::sw_q_state[q_id]->up_core_id != core_id) {
    return 1;
  }
  // RCore not assigned to sw_q
  if (bess::ctrl::sw_q_state[q_id]->down_core_id == DEFAULT_INVALID_CORE_ID) {
    return 2;
  }

  cpu_core_t down = bess::ctrl::sw_q_state[q_id]->down_core_id;
  if (down == DEFAULT_NFVCTRL_CORE_ID) {
    // Queue has been assigned to nfv_ctrl for dumping.
    this->RemoveQueue(bess::ctrl::sw_q[q_id]);
    bess::ctrl::sw_q_state[q_id]->down_core_id = DEFAULT_INVALID_CORE_ID;
    return 3;
  }

  // Success
  bess::ctrl::nfv_rcores[down]->RemoveQueue(bess::ctrl::sw_q[q_id]);
  bess::ctrl::sw_q_state[q_id]->down_core_id = DEFAULT_INVALID_CORE_ID;
  bess::ctrl::rcore_state[down] = true;
  return 0;
}

void NFVCtrl::NotifyCtrlLoadBalanceNow(uint16_t core_id) {
  rte_atomic16_set(&is_rebalancing_load_now_, core_id + 1);
}

CommandResponse NFVCtrl::Init(const bess::pb::NFVCtrlArg &arg) {
  bess::ctrl::nfv_ctrl = this;
  bess::ctrl::NFVCtrlCheckAllComponents();

  task_id_t tid = RegisterTask(nullptr);
  if (tid == INVALID_TASK_ID) {
    return CommandFailure(ENOMEM, "Task creation failed");
  }

  worker_id_ = 0;
  if (arg.wid() > 0) {
    worker_id_ = arg.wid();
  }

  total_core_count_ = 0;
  for (const auto& core_addr : arg.core_addrs()) {
    cpu_cores_.push_back(
      WorkerCore {
        core_id: total_core_count_,
        worker_port: core_addr.l2_port(),
        nic_addr: core_addr.l2_mac()}
    );
    total_core_count_ += 1;
  }
  assert(total_core_count_ == cpu_cores_.size());

  long_epoch_period_ns_ = LONG_TERM_UPDATE_PERIOD_NS;
  if (arg.long_epoch_period_ns() > 0) {
    long_epoch_period_ns_ = (uint64_t)arg.long_epoch_period_ns();
  }
  curr_ts_ns_ = tsc_to_ns(rdtsc());
  last_long_epoch_end_ns_ = curr_ts_ns_;

  if (arg.slo_ns() > 0) {
    bess::utils::slo_ns = arg.slo_ns();
  }

  // By default, open the example NF profile
  std::string long_profile_fname = "long_term_threshold";
  if (arg.nf_long_term_profile().size() > 0) {
    long_profile_fname = arg.nf_long_term_profile();
  }

  std::ifstream long_profile_file(long_profile_fname, std::ifstream::in);
  if (long_profile_file.is_open()) {
    while (!long_profile_file.eof()) {
      double pps;
      double flow_count;
      long_profile_file >> flow_count;
      long_profile_file >> pps;
      bess::ctrl::long_flow_count_pps_threshold[flow_count] = pps;
    }
    long_profile_file.close();
    LOG(INFO) << "Long-term NF profile " + long_profile_fname;
    LOG(INFO) << "Points: " << bess::ctrl::long_flow_count_pps_threshold.size();
  } else {
    LOG(INFO) << "Failed to read " + long_profile_fname;
  }

  std::string short_profile_fname = "nf_profiles/short_term.pro";
  std::ifstream short_profile_file(short_profile_fname, std::ifstream::in);
  if (short_profile_file.is_open()) {
    while (!short_profile_file.eof()) {
      uint32_t pkt_count;
      uint32_t flow_count;
      short_profile_file >> flow_count;
      short_profile_file >> pkt_count;
      bess::ctrl::short_flow_count_pkt_threshold[flow_count] = pkt_count;
    }
    short_profile_file.close();
    LOG(INFO) << "Short-term NF profile " + short_profile_fname;
    LOG(INFO) << "Points: " << bess::ctrl::short_flow_count_pkt_threshold.size();
  } else {
    LOG(INFO) << "Failed to read " + short_profile_fname;
  }

  qid_ = 0;
  if (arg.qid() > 0) {
    qid_ = arg.qid();
  }

  // Assign |to_add_queue_| and |to_remove_queue_| so that NFVCtrl
  // can dump packets in software queues for NFVCore and NFVRCore.
  size_t kQQSize = 64;
  int bytes = llring_bytes_with_slots(kQQSize);
  to_add_queue_ = reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));
  if (to_add_queue_) {
    llring_init(to_add_queue_, kQQSize, 0, 1);
  } else {
    LOG(ERROR) << "failed to allocate to_add_queue_";
  }
  to_remove_queue_ = reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));
  if (to_remove_queue_) {
    llring_init(to_remove_queue_, kQQSize, 0, 1);
  } else {
    LOG(ERROR) << "failed to allocate to_remove_queue_";
  }

  // Run!
  rte_atomic16_set(&is_rebalancing_load_now_, 0);
  rte_atomic16_set(&mark_to_disable_, 0);
  rte_atomic16_set(&disabled_, 0);
  return CommandSuccess();
}

void NFVCtrl::DeInit() {
  // Mark to stop the pipeline and wait until the pipeline stops
  rte_atomic16_set(&is_rebalancing_load_now_, 0);
  rte_atomic16_set(&mark_to_disable_, 1);
  while (rte_atomic16_read(&disabled_) == 0) { usleep(100000); }

  llring* q;
  if (to_add_queue_) {
    while (llring_sc_dequeue(to_add_queue_, (void **)&q) == 0) { continue; }
    std::free(to_add_queue_);
    to_add_queue_ = nullptr;
  }

  if (to_remove_queue_) {
    while (llring_sc_dequeue(to_remove_queue_, (void **)&q) == 0) { continue; }
    std::free(to_remove_queue_);
    to_remove_queue_ = nullptr;
  }

  bess::ctrl::nfv_ctrl = nullptr;
}

CommandResponse NFVCtrl::CommandGetSummary(const bess::pb::EmptyArg &arg) {
  for (const auto& it : ModuleGraph::GetAllModules()) {
    if (it.first.find("nfv_monitor") != std::string::npos) {
      ((NFVMonitor *)(it.second))->CommandGetSummary(arg);
    }
  }
  return CommandSuccess();
}

struct task_result NFVCtrl::RunTask(Context *, bess::PacketBatch *batch, void *) {
  if (port_ == nullptr) {
    return {.block = false, .packets = 1, .bits = 1};
  }

  uint64_t curr_ts_ns = tsc_to_ns(rdtsc());
  if (curr_ts_ns - last_long_epoch_end_ns_ > long_epoch_period_ns_) {
    // Default long-term op
    // For graceful termination
    if (rte_atomic16_read(&mark_to_disable_) == 1) {
      rte_atomic16_set(&disabled_, 1);
      return {.block = false, .packets = 1, .bits = 1};
    }
    if (rte_atomic16_read(&disabled_) == 1) {
      return {.block = false, .packets = 1, .bits = 1};
    }

    // Re-group RSS buckets to cores to adpat to long-term load changes
    uint32_t moves = LongEpochProcess();
    last_long_epoch_end_ns_ = tsc_to_ns(rdtsc());
    if (false && moves > 0) {
      LOG(INFO) << "Long-term op: default, time = " << last_long_epoch_end_ns_;
    }
  } else {
    // On-demand long-term op
    uint16_t core_id = rte_atomic16_read(&is_rebalancing_load_now_);
    if (core_id > 0) {
      core_id -= 1;
      if (curr_ts_ns - last_long_epoch_end_ns_ > MIN_NIC_RSS_UPDATE_PERIOD_NS) {
        // Re-group RSS buckets to cores to adpat to long-term load changes
        uint32_t moves = OnDemandLongEpochProcess(core_id);
        last_long_epoch_end_ns_ = tsc_to_ns(rdtsc());
        if (false && moves > 0) {
          LOG(INFO) << "Long-term op: on-demand, time = " << last_long_epoch_end_ns_;
        }
      }

      rte_atomic16_set(&is_rebalancing_load_now_, 0);
    }
  }

  // The following is a factory that dumps packets (in batch) that won't
  // be processed by any Cores or RCores.
  // WHy do we need this?
  // A: if we don't free packets, these packets will accumulate. They
  // will use all free packet memory slots and prevent new incoming
  // packets from entering the server.

  // 1) check |remove|. These |sw_q| must be removed from |to_dump_sw_q_|.
  llring* q = nullptr;
  while (llring_count(to_remove_queue_) > 0) {
    llring_sc_dequeue(to_remove_queue_, (void**)&q);
    if (q != NULL) {
      auto it = std::find(to_dump_sw_q_.begin(), to_dump_sw_q_.end(), q);
      if (it != to_dump_sw_q_.end()) {
        to_dump_sw_q_.erase(it);
      }
    }
    LOG(INFO) << "nfvctrl: to remove " << q << "; total = " << to_dump_sw_q_.size();
  }

  // 2) check |add|. These |sw_q| must be added to |to_dump_sw_q_|.
  while (llring_count(to_add_queue_) > 0) {
    llring_sc_dequeue(to_add_queue_, (void**)&q);
    if (q != NULL) {
      auto it = std::find(to_dump_sw_q_.begin(), to_dump_sw_q_.end(), q);
      if (it == to_dump_sw_q_.end()) {
        to_dump_sw_q_.push_back(q);
      }
    }
    LOG(INFO) << "nfvctrl: to add " << q << "; total = " << to_dump_sw_q_.size();
  }

  // |to_dump_sw_q_| contains |sw_q| that cannot be assigned to a RCore.
  // Just simply dump all packets for them.
  if (to_dump_sw_q_.size() > 0) {
    for (auto& it : to_dump_sw_q_) {
      if (it != NULL) {
        DumpOnceSoftwareQueue(it, batch);
      }
    }
  }

  return {.block = false, .packets = 1, .bits = 1};
}

void NFVCtrl::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  RunNextModule(ctx, batch); // To avoid [-Werror=unused-parameter] error
}

ADD_MODULE(NFVCtrl, "nfv_ctrl", "The per-worker NFV controller that interacts with NFVCore and NFVMonitor")
