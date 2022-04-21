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
#define HEAD_ROOM 0.1

namespace {
std::chrono::milliseconds DEFAULT_SLEEP_DURATION(100);
} // namespace

/// Initialize global NFV control messages
namespace bess {
namespace ctrl {

NFVCtrl* nfv_ctrl = nullptr;

NFVCore* nfv_cores[DEFAULT_INVALID_CORE_ID] = {nullptr};

NFVRCore* nfv_rcores[DEFAULT_INVALID_CORE_ID] = {nullptr};

struct llring* sw_q[DEFAULT_SWQ_COUNT] = {nullptr};

SoftwareQueue* sw_q_state[DEFAULT_SWQ_COUNT] = {nullptr}; // sw_q can be assigned if |up_core_id| is invalid

bool rcore_state[DEFAULT_INVALID_CORE_ID] = {false}; // rcore can be assigned if true

// Global software queue / reserved core management functions

void NFVCtrlMsgInit(int slots) {
  int bytes = llring_bytes_with_slots(slots);
  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    sw_q[i] =
        reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));

    // Note: each SoftwareQueue object has to be initialized as
    // 'rte_malloc' does not initialize it when allocating memory
    sw_q_state[i] =
        reinterpret_cast<SoftwareQueue *>(std::aligned_alloc(alignof(SoftwareQueue), sizeof(SoftwareQueue)));
    sw_q_state[i]->up_core_id = DEFAULT_INVALID_CORE_ID;
    sw_q_state[i]->down_core_id = DEFAULT_INVALID_CORE_ID;
  }

  LOG(INFO) << "NFV control messages are initialized";
}

void NFVCtrlMsgDeInit() {
  struct llring *q = nullptr;
  SoftwareQueue *q_state = nullptr;
  bess::Packet *pkt = nullptr;

  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    q = sw_q[i];
    if (q) {
      while (llring_sc_dequeue(q, (void **)&pkt) == 0) {
        bess::Packet::Free(pkt);
      }
      std::free(q);
    }
    q = nullptr;

    q_state = sw_q_state[i];
    if (q_state) {
      std::free(q_state);
    }
    q_state = nullptr;
  }

  LOG(INFO) << "NFV control messages are de-initialized";
}

// Transfer the ownership of (at most) |n| software packet queues
// to NFVCore (who calls this function)
uint64_t NFVCtrlRequestNSwQ(cpu_core_t core_id, int n) {
  if (nfv_cores[core_id] == nullptr) {
    LOG(ERROR) << "Core " << core_id << " is used but not created";
    // To register all normal CPU cores
    for (int i = 0; i < DEFAULT_INVALID_CORE_ID; i++){
      std::string core_name = "nfv_core" + std::to_string(i);
      for (const auto &it : ModuleGraph::GetAllModules()) {
        if (it.first.find(core_name) != std::string::npos) {
          nfv_cores[i] = ((NFVCore *)(it.second));
        }
      }
    }
  }

  if (nfv_ctrl == nullptr) {
    LOG(ERROR) << "NFVCtrl is used but not created";
    return 0;
  }

  return nfv_ctrl->RequestNSwQ(core_id, n);
}

void NFVCtrlReleaseNSwQ(cpu_core_t core_id, uint64_t q_mask) {
  nfv_ctrl->ReleaseNSwQ(core_id, q_mask);
}

bool NFVCtrlNotifyRCoreToWork(cpu_core_t core_id, int q_id) {
  return nfv_ctrl->NotifyRCoreToWork(core_id, q_id);
}

void NFVCtrlNotifyRCoreToRest(cpu_core_t core_id, int q_id) {
  nfv_ctrl->NotifyRCoreToRest(core_id, q_id);
}

} // namespace ctrl
} // namespace bess

// NFVCtrl helper functions

// Query the Gurobi optimization server to get a core assignment scheme.
void WriteToGurobi(uint32_t num_cores, std::vector<float> flow_rates, float latency_bound) {
  LOG(INFO) << num_cores << flow_rates.size() << latency_bound;
  std::ofstream file_out;
  file_out.open("./gurobi_in");
  file_out << num_cores <<std::endl;
  file_out << flow_rates.size() << std::endl;
  file_out << std::fixed <<latency_bound <<std::endl;
  for (auto &it : flow_rates) {
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

      // Find a (idle) reserved core
      for (int j = 0; j < DEFAULT_INVALID_CORE_ID; j++) {
        if (!bess::ctrl::rcore_state[j]) {
          continue;
        }

        bess::ctrl::rcore_state[j] = false;
        bess::ctrl::nfv_rcores[j]->AddQueue(bess::ctrl::sw_q[i]);
        bess::ctrl::sw_q_state[i]->down_core_id = j;
        break;
      }
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

bool NFVCtrl::NotifyRCoreToWork(cpu_core_t core_id, int q_id) {
  const std::lock_guard<std::mutex> lock(sw_q_mtx_);

  // Do not assign if sw_q |q_id| does not belong to NFVCore |core_id|
  if (bess::ctrl::sw_q_state[q_id]->up_core_id != core_id) {
    return false;
  }

  // Find an idle reserved core
  for (int i = 0; i < DEFAULT_INVALID_CORE_ID; i++) {
    if (!bess::ctrl::rcore_state[i]) {
      continue;
    }

    bess::ctrl::rcore_state[i] = false;
    bess::ctrl::nfv_rcores[i]->AddQueue(bess::ctrl::sw_q[q_id]);
    bess::ctrl::sw_q_state[q_id]->down_core_id = i;
    return true;
  }
  return false;
}

void NFVCtrl::NotifyRCoreToRest(cpu_core_t core_id, int q_id) {
  const std::lock_guard<std::mutex> lock(sw_q_mtx_);

  // RCore not assigned to sw_q
  if (bess::ctrl::sw_q_state[q_id]->down_core_id == DEFAULT_INVALID_CORE_ID) {
    return;
  }
  // Do not change if sw_q |q_id| does not belong to NFVCore |core_id|
  if (bess::ctrl::sw_q_state[q_id]->up_core_id != core_id) {
    return;
  }

  cpu_core_t down = bess::ctrl::sw_q_state[q_id]->down_core_id;
  bess::ctrl::nfv_rcores[down]->RemoveQueue(bess::ctrl::sw_q[q_id]);
  bess::ctrl::rcore_state[down] = true; // reset so that it can be assigned later
  bess::ctrl::sw_q_state[q_id]->down_core_id = DEFAULT_INVALID_CORE_ID;
}

CommandResponse NFVCtrl::Init(const bess::pb::NFVCtrlArg &arg) {
  bess::ctrl::nfv_ctrl = this;
  bess::ctrl::NFVCtrlMsgInit(1024);

  task_id_t tid = RegisterTask(nullptr);
  if (tid == INVALID_TASK_ID) {
    return CommandFailure(ENOMEM, "Task creation failed");
  }

  total_core_count_ = 0;
  long_epoch_update_period_ = LONG_TERM_UPDATE_PERIOD;
  long_epoch_last_update_time_ = tsc_to_ns(rdtsc());
  for (const auto &core_addr : arg.core_addrs()) {
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

  if (!arg.port().empty()) {
    const char *port_name = arg.port().c_str();
    const auto &it = PortBuilder::all_ports().find(port_name);
    if (it == PortBuilder::all_ports().end()) {
      LOG(INFO) << "Failed to find port";
      return CommandFailure(ENODEV, "Port %s not found", port_name);
    }
    port_ = ((PMDPort*)it->second);
    //create and save the core to bucket mapping
    for (uint16_t i = 0; i < total_core_count_; i++) {
      core_bucket_mapping_[i] = std::vector<uint16_t>();
    }
    for(uint16_t i = 0; i < port_->reta_size_; i++) {
      uint16_t core_id = port_->reta_table_[i];
      assert(core_id < total_core_count_);
      core_bucket_mapping_[core_id].push_back(i);
    }
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

// Apply first-fit to find the best core for the RSS bucket
std::map<uint16_t, uint16_t> NFVCtrl::FindMoves(std::vector<double>& per_cpu_pkt_rate, std::vector<uint16_t>& to_be_moved, const std::vector<double>& per_bucket_pkt_rate) {
  std::map<uint16_t, uint16_t> moves;
  for (auto it : to_be_moved) {
    double flow_rate = per_bucket_pkt_rate[it];
    bool found = false;
    for (uint16_t i = 0; i < total_core_count_; i++) {
      if (per_cpu_pkt_rate[i] > 0 && per_cpu_pkt_rate[i] + flow_rate < (flow_count_pps_threshold_[10000] * (1-HEAD_ROOM))) {
        per_cpu_pkt_rate[i] += flow_rate;
        moves[it] = i;
        core_bucket_mapping_[i].push_back(it);
        found = true;
        break;
      }
    }

    // No core found. Need to add a new CPU
    if (!found) {
      for (uint16_t i = 0; i < total_core_count_; i++) {
        if (per_cpu_pkt_rate[i] == 0) {
          per_cpu_pkt_rate[i] += flow_rate;
          moves[it] = i;
          core_bucket_mapping_[i].push_back(it);
          found = true;
          break;
        }
      }

      if (!found) {
        // Not enough CPUs to hand the load. Note: this should never happen
        LOG(INFO) << "No new CPU found for the flow: " << flow_rate;
      }
    }
  }
  return moves;
}

std::map<uint16_t, uint16_t> NFVCtrl::LongTermOptimization(const std::vector<double>& per_bucket_pkt_rate) {
  // Compute the aggregated flow rate per core
  std::vector<double> per_cpu_pkt_rate (total_core_count_);
  for (uint16_t i = 0; i < total_core_count_; i++) {
    per_cpu_pkt_rate[i] = 0;
    for (auto it : core_bucket_mapping_[i]) {
      per_cpu_pkt_rate[i] += per_bucket_pkt_rate[it];
    }
  }

  std::vector<uint16_t> to_be_moved;
  // Find if any core is exceeding threshold and add it to the to be moved list
  for (uint16_t i = 0; i < total_core_count_; i++) {
    while (per_cpu_pkt_rate[i] > flow_count_pps_threshold_[10000]) {
      // Find a bucket to move and do this till all flow rate comes down the threshold
      uint16_t bucket = core_bucket_mapping_[i].back();
      to_be_moved.push_back(bucket);
      core_bucket_mapping_[i].pop_back();
      per_cpu_pkt_rate[i] -= per_bucket_pkt_rate[bucket];
    }
  }

  // Find a cpu for the buckets to be moved
  // we should pass per_cpu_pkt_rate by reference
  std::map<uint16_t, uint16_t> moves = FindMoves(per_cpu_pkt_rate, to_be_moved, per_bucket_pkt_rate);

  // Find the CPU with minimum flow rate and delete it
  uint16_t smallest_core = 0;
  double min_flow = per_cpu_pkt_rate[0];
  for(uint16_t i = 1; i < total_core_count_; i++) {
    // We check greater than 0 to avoid idle cores
    if (per_cpu_pkt_rate[i] != 0 && min_flow == 0) {
      smallest_core = i;
      min_flow = per_cpu_pkt_rate[i];
      continue;
    }
    if (per_cpu_pkt_rate[i] < min_flow && per_cpu_pkt_rate[i] > 0) {
      min_flow = per_cpu_pkt_rate[i];
      smallest_core = i;
    }
  }
  per_cpu_pkt_rate[smallest_core] = flow_count_pps_threshold_[10000];
  std::vector<uint16_t> old_buckets = core_bucket_mapping_[smallest_core];
  std::map<uint16_t, uint16_t> moves_tmp = FindMoves(per_cpu_pkt_rate, core_bucket_mapping_[smallest_core], per_bucket_pkt_rate);
  if (moves_tmp.size() != old_buckets.size()) {
    per_cpu_pkt_rate[smallest_core] = min_flow;
    for (auto &it: moves_tmp) {
      // Undo all changes if this trial fails
      core_bucket_mapping_[it.second].pop_back();
      per_cpu_pkt_rate[it.second] -= per_bucket_pkt_rate[it.first];
    }
    moves_tmp.clear();
  } else {
    core_bucket_mapping_[smallest_core].clear();
  }

  moves.insert(moves_tmp.begin(), moves_tmp.end());
  return moves;
}

void NFVCtrl::UpdateFlowAssignment() {
  std::vector<double> per_bucket_pkt_rate;

  bess::utils::bucket_stats.bucket_table_lock.lock();
  for (int i = 0; i < RETA_SIZE; i++) {
    per_bucket_pkt_rate.push_back(bess::utils::bucket_stats.per_bucket_packet_counter[i]*1000000000/long_epoch_update_period_);
    bess::utils::bucket_stats.per_bucket_packet_counter[i] = 0;
  }
  bess::utils::bucket_stats.bucket_table_lock.unlock();

  std::map<uint16_t, uint16_t> moves = LongTermOptimization(per_bucket_pkt_rate);

  // Create reta table and upadate rss
  port_->UpdateRssReta(moves);
}

void NFVCtrl::DeInit() {
  bess::ctrl::nfv_ctrl = nullptr;
  bess::ctrl::NFVCtrlMsgDeInit();
}

CommandResponse NFVCtrl::CommandGetSummary(const bess::pb::EmptyArg &arg) {
  for (const auto &it : ModuleGraph::GetAllModules()) {
    if (it.first.find("nfv_monitor") != std::string::npos) {
      ((NFVMonitor *)(it.second))->CommandGetSummary(arg);
    }
  }
  return CommandSuccess();
}

struct task_result NFVCtrl::RunTask(Context *ctx, bess::PacketBatch *batch, void *) {
  uint64_t curr_ts_ns = tsc_to_ns(rdtsc());
  if (curr_ts_ns - long_epoch_last_update_time_ > long_epoch_update_period_) {
    UpdateFlowAssignment();
    long_epoch_last_update_time_ = curr_ts_ns;
  }

  RunNextModule(ctx, batch); // To avoid [-Werror=unused-parameter] error
  return {.block = false, .packets = 0, .bits = 0};
}

void NFVCtrl::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  RunNextModule(ctx, batch); // To avoid [-Werror=unused-parameter] error
}

ADD_MODULE(NFVCtrl, "nfv_ctrl", "The per-worker NFV controller that interacts with NFVCore and NFVMonitor")
