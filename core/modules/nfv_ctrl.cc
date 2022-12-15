#include "nfv_ctrl.h"
#include "nfv_ctrl_msg.h"
#include "nfv_core.h"
#include "nfv_rcore.h"
#include "nfv_monitor.h"

#include "../module_graph.h"

// The time interval for the long term optimization to run
#define LONG_TERM_UPDATE_PERIOD_NS 500000000
#define MIN_NIC_RSS_UPDATE_PERIOD_NS 50000000

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
}
#pragma GCC diagnostic pop
} // namespace

/// NFVCtrl's own functions:
const Commands NFVCtrl::cmds = {
    {"get_summary", "EmptyArg", MODULE_CMD_FUNC(&NFVCtrl::CommandGetSummary),
     Command::THREAD_SAFE},
};

std::vector<int> NFVCtrl::RequestNSwQ(cpu_core_t core_id, int n) {
  std::vector<int> assigned;
  if (core_id == DEFAULT_INVALID_CORE_ID) {
    return assigned;
  }

  // Only one NFVCore can call the following session at a time.
  const std::lock_guard<std::mutex> lock(sw_q_mtx_);

  // Find a (idle) software queue
  for (int i = 0; (i < DEFAULT_SWQ_COUNT) && (int(assigned.size()) < n); i++) {
    if (bess::ctrl::sw_q_state[i]->GetUpCoreID() == DEFAULT_INVALID_CORE_ID) {
      assigned.push_back(i);
      bess::ctrl::sw_q_state[i]->SetUpCoreID(core_id);
    }
  }
  return assigned;
}

int NFVCtrl::RequestSwQ(cpu_core_t core_id) {
  if (core_id == DEFAULT_INVALID_CORE_ID) {
    return DEFAULT_SWQ_COUNT;
  }

  // Only one NFVCore can call the following session at a time.
  const std::lock_guard<std::mutex> lock(sw_q_mtx_);

  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    if (bess::ctrl::sw_q_state[i]->GetUpCoreID() == DEFAULT_INVALID_CORE_ID) {
      bess::ctrl::sw_q_state[i]->SetUpCoreID(core_id);
      return i;
    }
  }
  return DEFAULT_SWQ_COUNT;
}

void NFVCtrl::ReleaseNSwQ(cpu_core_t core_id, std::vector<int> qids) {
  const std::lock_guard<std::mutex> lock(sw_q_mtx_);

  for (auto qid : qids) {
    if (qid >= 0 ||
        qid < DEFAULT_SWQ_COUNT ||
        bess::ctrl::sw_q_state[qid]->GetUpCoreID() == core_id) {
      bess::ctrl::sw_q_state[qid]->SetUpCoreID(DEFAULT_INVALID_CORE_ID);
    }
  }
}

void NFVCtrl::ReleaseSwQ(int q_id) {
  const std::lock_guard<std::mutex> lock(sw_q_mtx_);

  bess::ctrl::sw_q_state[q_id]->SetUpCoreID(DEFAULT_INVALID_CORE_ID);
}

int NFVCtrl::NotifyRCoreToWork(cpu_core_t core_id, int q_id) {
  const std::lock_guard<std::mutex> lock(sw_q_mtx_);

  cpu_core_t up = bess::ctrl::sw_q_state[q_id]->GetUpCoreID();
  cpu_core_t down = bess::ctrl::sw_q_state[q_id]->GetDownCoreID();

  // Do not assign if sw_q |q_id| does not belong to NFVCore |core_id|
  if (up != core_id) {
    return 1;
  }
  // Do not assign if sw_q |q_id| has already been assigned
  if (down != DEFAULT_INVALID_CORE_ID) {
    return 2;
  }

  // Find an idle reserved core
  // [0, ncore - 1] are used for core-boost.
  // [ncore, rcore - 1] are used for offloading.
  for (uint16_t i = bess::ctrl::ncore; i < (uint16_t)bess::ctrl::rcore; i++) {
    if (bess::ctrl::nfv_rcores[i] == nullptr ||
        !bess::ctrl::rcore_state[i]) {
      continue;
    }
    // Success
    bess::ctrl::rcore_state[i] = false;
    bess::ctrl::nfv_rcores[i]->AddQueue(q_id);
    return 0;
  }

  // No RCores found. System Overloaded! Hand-off to NFVCtrl
  this->AddQueue(bess::ctrl::sw_q[q_id]);
  bess::ctrl::sw_q_state[q_id]->SetDownCoreID(DEFAULT_NFVCTRL_CORE_ID);
  return 3;
}

int NFVCtrl::NotifyRCoreToRest(cpu_core_t core_id, int q_id) {
  const std::lock_guard<std::mutex> lock(sw_q_mtx_);

  cpu_core_t up = bess::ctrl::sw_q_state[q_id]->GetUpCoreID();
  cpu_core_t down = bess::ctrl::sw_q_state[q_id]->GetDownCoreID();

  // Do not change if sw_q |q_id| does not belong to NFVCore |core_id|
  if (up != core_id) {
    return 1;
  }
  // RCore not assigned to sw_q
  if (down == DEFAULT_INVALID_CORE_ID) {
    return 2;
  }

  if (down == DEFAULT_NFVCTRL_CORE_ID) {
    // Queue has been assigned to nfv_ctrl for dumping.
    this->RemoveQueue(bess::ctrl::sw_q[q_id]);
    bess::ctrl::sw_q_state[q_id]->SetDownCoreID(DEFAULT_INVALID_CORE_ID);
    return 3;
  }

  // Success
  bess::ctrl::nfv_rcores[down]->RemoveQueue(q_id);
  return 0;
}

int NFVCtrl::RequestRCore() {
  const std::lock_guard<std::mutex> lock(sw_q_mtx_);

  for (int i = 0; i < bess::ctrl::rcore; i++) {
    if (bess::ctrl::nfv_rcores[i] == nullptr ||
        !bess::ctrl::rcore_state[i]) {
      continue;
    }
    // Success
    bess::ctrl::rcore_state[i] = false;
    return i;
  }
  return -1;
}

int NFVCtrl::ReleaseRCore(int q_id) {
  const std::lock_guard<std::mutex> lock(sw_q_mtx_);

  bess::ctrl::nfv_rcores[q_id]->RemoveQueue(q_id);
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

  // |qid_| is for sending control-plane messages
  qid_ = 0;
  if (arg.qid() > 0) {
    qid_ = arg.qid();
  }

  total_core_count_ = 0;
  if (arg.ncore() > 0) {
    bess::ctrl::ncore = arg.ncore();
    total_core_count_ = bess::ctrl::ncore;
  }
  if (arg.rcore() > 0) {
    bess::ctrl::rcore = arg.rcore();
  }
  LOG(INFO) << "ncore: " << bess::ctrl::ncore << ", rcore: " << bess::ctrl::rcore;

  long_epoch_period_ns_ = LONG_TERM_UPDATE_PERIOD_NS;
  if (arg.long_epoch_period_ns() > 0) {
    long_epoch_period_ns_ = arg.long_epoch_period_ns();
  }
  curr_ts_ns_ = tsc_to_ns(rdtsc());
  last_long_epoch_end_ns_ = curr_ts_ns_;

  bess::utils::slo_ns = 1000000; // default: 1 ms
  if (arg.slo_ns() > 0) {
    bess::utils::slo_ns = arg.slo_ns();
  }
  LOG(INFO) << "target slo: " << bess::utils::slo_ns / 1000 << " us; Ironside long period: " << long_epoch_period_ns_ / 1000 << " us";

  // By default, open the example NF profile
  std::string long_profile_fname = "long_term_threshold";
  if (arg.nf_long_term_profile().size() > 0) {
    long_profile_fname = arg.nf_long_term_profile();
  }

  std::ifstream long_profile_file(long_profile_fname, std::ifstream::in);
  if (long_profile_file.is_open()) {
    while (!long_profile_file.eof()) {
      uint64_t pps;
      uint64_t flow_count;
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
  if (arg.nf_short_term_profile().size() > 0) {
    short_profile_fname = arg.nf_short_term_profile();
  }
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

  if (arg.exp_id() > 0) {
    bess::ctrl::exp_id = (int)arg.exp_id();
    LOG(INFO) << "Ironside exp: " << bess::ctrl::exp_id;
  }

  // Waiting for long-term stats from all ncores
  msg_mode_ = false;
  rte_atomic16_set(&long_term_stats_ready_cores_, 0);

  std::string ingress_ip = "10.10.1.1";
  bess::utils::ParseIpv4Address(ingress_ip, &monitor_dst_ip_);

  // Run!
  rte_atomic16_set(&is_rebalancing_load_now_, 0);
  rte_atomic16_set(&disabled_, 0);
  return CommandSuccess();
}

void NFVCtrl::DeInit() {
  // Mark to stop the pipeline and wait until the pipeline stops
  rte_atomic16_set(&is_rebalancing_load_now_, 0);
  rte_atomic16_set(&disabled_, 1);
  while (rte_atomic16_read(&disabled_) != 2) { usleep(100000); }

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
    if (!msg_mode_) {
      for (int i = 0; i < bess::ctrl::ncore; i++) {
        bess::ctrl::nfv_cores[i]->UpdateBucketStats();
      }
      msg_mode_ = true;
      goto cleanup;
    }

    if (rte_atomic16_read(&long_term_stats_ready_cores_) != bess::ctrl::ncore) {
      goto cleanup;
    }

    rte_atomic16_set(&long_term_stats_ready_cores_, 0);
    msg_mode_ = false;

    // Default long-term op
    // Re-group RSS buckets to cores to adpat to long-term load changes
    uint32_t moves = LongEpochProcess();
    if (moves > 0) {
      LOG(INFO) << "Long-term op: default, time = " << last_long_epoch_end_ns_;
    }
    rte_atomic16_set(&is_rebalancing_load_now_, 0);
    last_long_epoch_end_ns_ = tsc_to_ns(rdtsc());

    // For graceful termination
    if (rte_atomic16_read(&disabled_) == 1) {
      rte_atomic16_set(&disabled_, 2);
      return {.block = false, .packets = 1, .bits = 1};
    }
  } else {
    // Exp 1: do we need the on-demand long-term invocation?
    if (true || bess::ctrl::exp_id == 2) {
      rte_atomic16_set(&is_rebalancing_load_now_, 0);
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
        // reset
        rte_atomic16_set(&is_rebalancing_load_now_, 0);
      }
    }
  }

cleanup:
  // |to_dump_sw_q_| contains |sw_q| that cannot be assigned to a RCore.
  // Just simply dump all packets for them.
  for (auto& it : to_dump_sw_q_) {
    if (it != NULL) {
      DumpOnceSoftwareQueue(it, batch);
    }
  }

  return {.block = false, .packets = 1, .bits = 1};
}

void NFVCtrl::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  // To avoid [-Werror=unused-parameter] error
  RunNextModule(ctx, batch);
}

ADD_MODULE(NFVCtrl, "nfv_ctrl", "The per-worker NFV controller that interacts with NFVCore and NFVMonitor")
