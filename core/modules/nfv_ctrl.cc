#include "nfv_ctrl.h"
#include "nfv_ctrl_msg.h"
#include "nfv_core.h"
#include "nfv_rcore.h"
#include "nfv_monitor.h"

#include <chrono>
#include <thread>

#include "../module_graph.h"
#include "../utils/sys_measure.h"

// The time interval for the long term optimization to run
#define LONG_TERM_UPDATE_PERIOD 500000000

// The amount of space to leave when packing buckets into CPUs
#define MIGRATE_HEAD_ROOM 0.1
#define ASSIGN_HEAD_ROOM 0.2

namespace {
std::chrono::milliseconds DEFAULT_SLEEP_DURATION(100);
} // namespace

/// NFVCtrl helper functions

// Query the Gurobi optimization server to get a core assignment scheme.
void WriteToGurobi(uint32_t num_cores, std::vector<float> flow_rates, float latency_bound) {
  LOG(INFO) << num_cores << flow_rates.size() << latency_bound;
  std::ofstream file_out;
  file_out.open("./gurobi_in");
  file_out << num_cores <<std::endl;
  file_out << flow_rates.size() << std::endl;
  file_out << std::fixed <<latency_bound <<std::endl;
  for (auto& it : flow_rates) {
    file_out << it<< std::endl;
  }
  file_out.close();
}

/// NFVCtrl's own functions

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

    bess::ctrl::rcore_state[i] = false;
    bess::ctrl::nfv_rcores[i]->AddQueue(bess::ctrl::sw_q[q_id]);
    bess::ctrl::sw_q_state[q_id]->down_core_id = i;
    return 0;
  }
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
  bess::ctrl::nfv_rcores[down]->RemoveQueue(bess::ctrl::sw_q[q_id]);
  bess::ctrl::rcore_state[down] = true; // reset so that it can be assigned later
  bess::ctrl::sw_q_state[q_id]->down_core_id = DEFAULT_INVALID_CORE_ID;
  return 0;
}

CommandResponse NFVCtrl::Init(const bess::pb::NFVCtrlArg &arg) {
  bess::ctrl::nfv_ctrl = this;
  bess::ctrl::NFVCtrlMsgInit(1024);
  bess::ctrl::NFVCtrlCheckAllComponents();

  task_id_t tid = RegisterTask(nullptr);
  if (tid == INVALID_TASK_ID) {
    return CommandFailure(ENOMEM, "Task creation failed");
  }

  total_core_count_ = 0;
  long_epoch_update_period_ = LONG_TERM_UPDATE_PERIOD;
  long_epoch_last_update_time_ = tsc_to_ns(rdtsc());
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

  curr_ts_ns_ = 0;

  if (arg.slo_ns() > 0) {
    bess::utils::slo_ns = arg.slo_ns();
  }

  std::ifstream file("long_term_threshold", std::ifstream::in);
  if (file.is_open()) {
    while (!file.eof()) {
      uint64_t pps;
      uint64_t flow_count;
      file >> flow_count;
      file >> pps;
      flow_count_pps_threshold_[flow_count] = pps;
    }
    file.close();
  }

  return CommandSuccess();
}

void NFVCtrl::InitPMD(PMDPort* port) {
  if (port == nullptr) {
    return;
  }

  port_ = port;
  // Init the core-bucket mapping
  for (uint16_t i = 0; i < total_core_count_; i++) {
    core_bucket_mapping_[i] = std::vector<uint16_t>();
  }
  for(uint16_t i = 0; i < port_->reta_size_; i++) {
    uint16_t core_id = port_->reta_table_[i];
    core_bucket_mapping_[core_id].push_back(i);
  }

  active_core_count_ = 0;
  for (uint16_t i = 0; i < total_core_count_; i++) {
    if (core_bucket_mapping_[i].size() > 0) {
      bess::ctrl::core_state[i] = true;
      active_core_count_ += 1;
    }
  }

  LOG(INFO) << "NIC init: " << active_core_count_ << " active normal cores";
  // port_->UpdateRssReta();
  port_->UpdateRssFlow();
}

std::map<uint16_t, uint16_t> NFVCtrl::FindMoves(std::vector<double>& per_cpu_pkt_rate,
                                                std::vector<uint16_t>& to_move_buckets,
                                                const std::vector<double>& per_bucket_pkt_rate) {
  std::map<uint16_t, uint16_t> moves;
  for (auto bucket : to_move_buckets) {
    double bucket_pkt_rate = per_bucket_pkt_rate[bucket];
    bool found = false;
    for (uint16_t i = 0; i < total_core_count_; i++) {
      if (bess::ctrl::core_state[i] &&
          per_cpu_pkt_rate[i] + bucket_pkt_rate < (flow_count_pps_threshold_[10000] * (1 - ASSIGN_HEAD_ROOM))) {
        per_cpu_pkt_rate[i] += bucket_pkt_rate;
        moves[bucket] = i;
        core_bucket_mapping_[i].push_back(bucket);
        found = true;
        break;
      }
    }

    // No core found. Need to add a new core
    if (!found) {
      for (uint16_t i = 0; i < total_core_count_; i++) {
        if (!bess::ctrl::core_state[i]) {
          per_cpu_pkt_rate[i] += bucket_pkt_rate;
          moves[bucket] = i;
          core_bucket_mapping_[i].push_back(bucket);
          found = true;

          bess::ctrl::core_state[i] = true;
          bess::ctrl::core_liveness[i] = 1;
          active_core_count_ += 1;
          break;
        }
      }

      // No enough cores for handling the excessive load. Ideally, this should never happen
      if (!found) {
        LOG(INFO) << "No idle normal core found for bucket: " << bucket << " w/ rate: " << bucket_pkt_rate;
      }
    }
  }
  return moves;
}

std::map<uint16_t, uint16_t> NFVCtrl::LongTermOptimization(const std::vector<double>& per_bucket_pkt_rate) {
  // Compute the aggregated flow rate per core
  active_core_count_ = 0;
  std::vector<double> per_cpu_pkt_rate(total_core_count_);
  for (uint16_t i = 0; i < total_core_count_; i++) {
    per_cpu_pkt_rate[i] = 0;
    if (core_bucket_mapping_[i].size() > 0) {
      for (auto it : core_bucket_mapping_[i]) {
        per_cpu_pkt_rate[i] += per_bucket_pkt_rate[it];
      }
      bess::ctrl::core_state[i] = true;
      bess::ctrl::core_liveness[i] += 1;
      active_core_count_ += 1;
    }
  }

  // Find if any core is exceeding threshold and add it to the to be moved list
  std::vector<uint16_t> to_move_buckets;
  for (uint16_t i = 0; i < total_core_count_; i++) {
    if (!bess::ctrl::core_state[i]) {
      continue;
    }
    // Move a bucket and do this until the aggregated packet rate is below the threshold
    while (per_cpu_pkt_rate[i] > flow_count_pps_threshold_[10000] * (1 - MIGRATE_HEAD_ROOM) &&
          core_bucket_mapping_[i].size() > 0) {
      uint16_t bucket = core_bucket_mapping_[i].back();
      to_move_buckets.push_back(bucket);
      core_bucket_mapping_[i].pop_back();
      per_cpu_pkt_rate[i] -= per_bucket_pkt_rate[bucket];
      bess::ctrl::core_liveness[i] = 1;
    }
  }

  // For all buckets to be moved, assign them to a core
  std::map<uint16_t, uint16_t> moves = FindMoves(per_cpu_pkt_rate, to_move_buckets, per_bucket_pkt_rate);

  if (active_core_count_ == 1) {
    return moves;
  }

  // Find the CPU with minimum flow rate and delete it
  uint16_t min_rate_core = DEFAULT_INVALID_CORE_ID;
  double min_rate = 0;
  for(uint16_t i = 0; i < total_core_count_; i++) {
    if (!bess::ctrl::core_state[i] ||
        bess::ctrl::core_liveness[i] <= 4) {
      continue;
    }

    if (min_rate_core == DEFAULT_INVALID_CORE_ID) {
      min_rate_core = i;
      min_rate = per_cpu_pkt_rate[i];
      continue;
    }
    if (per_cpu_pkt_rate[i] < min_rate) {
      min_rate_core = i;
      min_rate = per_cpu_pkt_rate[i];
    }
  }

  // Do nothing to avoid oscillations. If:
  // - no min-rate core is found;
  // - the min-rate core's rate is too large;
  if (min_rate_core == DEFAULT_INVALID_CORE_ID ||
      min_rate > flow_count_pps_threshold_[10000] / 2) {
    return moves;
  }

  // Move all buckets at the min-rate core; before that, save the current state
  per_cpu_pkt_rate[min_rate_core] = flow_count_pps_threshold_[10000];
  int org_active_cores = active_core_count_;
  std::vector<uint16_t> org_buckets = core_bucket_mapping_[min_rate_core];

  std::map<uint16_t, uint16_t> tmp_moves = FindMoves(per_cpu_pkt_rate, core_bucket_mapping_[min_rate_core], per_bucket_pkt_rate);

  if (active_core_count_ > org_active_cores ||
      tmp_moves.size() != org_buckets.size()) {
    // If this trial fails, undo all changes
    // - case 1: |FindMoves| uses more cores;
    // - case 2: |org_buckets| cannot be fit into normal cores;
    per_cpu_pkt_rate[min_rate_core] = min_rate;
    for (auto& m_it : tmp_moves) {
      core_bucket_mapping_[m_it.second].pop_back();
      per_cpu_pkt_rate[m_it.second] -= per_bucket_pkt_rate[m_it.first];
    }
  } else {
    core_bucket_mapping_[min_rate_core].clear();
    for (auto& m_it : tmp_moves) {
      moves[m_it.first] = m_it.second;
    }

    bess::ctrl::core_state[min_rate_core] = false;
    active_core_count_ -= 1;
  }

  return moves;
}

void NFVCtrl::UpdateFlowAssignment() {
  std::vector<double> per_bucket_pkt_rate;
  uint64_t c = 1000000000ULL / long_epoch_update_period_;

  bess::utils::bucket_stats->bucket_table_lock.lock();
  for (int i = 0; i < RETA_SIZE; i++) {
    per_bucket_pkt_rate.push_back(bess::utils::bucket_stats->per_bucket_packet_counter[i] * c);
    bess::utils::bucket_stats->per_bucket_packet_counter[i] = 0;
  }
  bess::utils::bucket_stats->bucket_table_lock.unlock();

  std::map<uint16_t, uint16_t> moves = LongTermOptimization(per_bucket_pkt_rate);
  if (moves.size()) {
    if (port_) {
      // port_->UpdateRssReta(moves);
      port_->UpdateRssFlow(moves);
    }
    LOG(INFO) << "(UpdateFlowAssignment) moves: " << moves.size();
  }
}

void NFVCtrl::DeInit() {
  bess::ctrl::nfv_ctrl = nullptr;
  bess::ctrl::NFVCtrlMsgDeInit();
}

CommandResponse NFVCtrl::CommandGetSummary(const bess::pb::EmptyArg &arg) {
  for (const auto& it : ModuleGraph::GetAllModules()) {
    if (it.first.find("nfv_monitor") != std::string::npos) {
      ((NFVMonitor *)(it.second))->CommandGetSummary(arg);
    }
  }
  return CommandSuccess();
}

struct task_result NFVCtrl::RunTask(Context *, bess::PacketBatch *, void *) {
  if (port_ == nullptr) {
    return {.block = false, .packets = 0, .bits = 0};
  }

  uint64_t curr_ts_ns = tsc_to_ns(rdtsc());
  if (curr_ts_ns - long_epoch_last_update_time_ > long_epoch_update_period_) {
    UpdateFlowAssignment();
    long_epoch_last_update_time_ = curr_ts_ns;
  }

  return {.block = false, .packets = 0, .bits = 0};
}

void NFVCtrl::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  RunNextModule(ctx, batch); // To avoid [-Werror=unused-parameter] error
}

ADD_MODULE(NFVCtrl, "nfv_ctrl", "The per-worker NFV controller that interacts with NFVCore and NFVMonitor")
