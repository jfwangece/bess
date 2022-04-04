#include "nfv_ctrl.h"
#include "nfv_ctrl_msg.h"
#include "nfv_core.h"
#include "nfv_monitor.h"

#include <chrono>
#include <thread>

#include "../module_graph.h"
#include "../utils/sys_measure.h"

#define UPDATE_PERIOD 5000000000

namespace {
std::chrono::milliseconds DEFAULT_SLEEP_DURATION(100);
} // namespace

/// Initialize global NFV control messages

NFVCtrl *nfv_ctrl = nullptr;

NFVCore* nfv_cores[DEFAULT_INVALID_CORE_ID] = {nullptr};

struct llring* sw_q[DEFAULT_SWQ_COUNT] = {nullptr};

SoftwareQueue* sw_q_state[DEFAULT_SWQ_COUNT] = {nullptr};

void NFVCtrlMsgInit(int slots) {
  int bytes = llring_bytes_with_slots(slots);
  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    sw_q[i] =
        reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));
  }
}

void NFVCtrlMsgDeInit() {
  struct llring *q = nullptr;
  bess::Packet *pkt = nullptr;

  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    q = sw_q[i];
    if (q) {
      while (llring_sc_dequeue(q, (void **)&pkt) == 0) {
        bess::Packet::Free(pkt);
      }
    }
    std::free(q);
    q = nullptr;
  }
}

// Transfer the ownership of (at most) |n| software packet queues
// to NFVCore (who calls this function)
void NFVCtrlRequestSwQ(cpu_core_t core_id, int n) {
  if (nfv_cores[core_id] == nullptr) {
    for (int i = 0; i < DEFAULT_INVALID_CORE_ID; i++){
      std::string core_name = "nfv_core" + std::to_string(i);
      for (const auto &it : ModuleGraph::GetAllModules()) {
        if (it.first.find(core_name) != std::string::npos) {
          nfv_cores[i] = ((NFVCore *)(it.second));
        }
      }
    }
  }

  if (nfv_ctrl != nullptr) {
    uint64_t bitmask = nfv_ctrl->RequestNSwQ(core_id, n);
    if (bitmask > 0) {
      return;
    }
  }
}

/// NFVCtrl's own functions

const Commands NFVCtrl::cmds = {
    {"get_summary", "EmptyArg", MODULE_CMD_FUNC(&NFVCtrl::CommandGetSummary),
     Command::THREAD_SAFE},
};

uint64_t NFVCtrl::RequestNSwQ(cpu_core_t core_id, int n) {
  uint64_t bitmask = 0;
  if (core_id == DEFAULT_INVALID_CORE_ID) {
    return bitmask;
  }

  int cnt = 0;
  std::unique_lock lock(sw_q_mtx_);

  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    if (sw_q_state[i]->up_core_id == DEFAULT_INVALID_CORE_ID) {
      sw_q_state[i]->up_core_id = core_id;
      bitmask |= 1 << i;
    }
    if (cnt == n) {
      break;
    }
  }
  return bitmask;
}

int NFVCtrl::RequestSwQ(cpu_core_t core_id) {
  if (core_id == DEFAULT_INVALID_CORE_ID) {
    return DEFAULT_SWQ_COUNT;
  }

  int i;
  std::unique_lock lock(sw_q_mtx_);

  for (i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    if (sw_q_state[i]->up_core_id == DEFAULT_INVALID_CORE_ID) {
      sw_q_state[i]->up_core_id = core_id;
      return i;
    }
  }
  return i;
}

void NFVCtrl::ReleaseSwQ(int q_id) {
  std::unique_lock lock(sw_q_mtx_);

  if (q_id >= 0 && q_id < DEFAULT_SWQ_COUNT) {
    sw_q_state[q_id]->up_core_id = DEFAULT_INVALID_CORE_ID;
  }
}

CommandResponse NFVCtrl::Init(const bess::pb::NFVCtrlArg &arg) {
  nfv_ctrl = this;
  NFVCtrlMsgInit(1024);

  task_id_t tid = RegisterTask(nullptr);
  if (tid == INVALID_TASK_ID) {
    return CommandFailure(ENOMEM, "Task creation failed");
  }

  total_core_count_ = 0;
  long_epoch_update_period_ = UPDATE_PERIOD;
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
    LOG(INFO) << port_name;
    const auto &it = PortBuilder::all_ports().find(port_name);
    if (it == PortBuilder::all_ports().end()) {
      LOG(INFO) << "Failed to find port";
      return CommandFailure(ENODEV, "Port %s not found", port_name);
    }
    port_ = ((PMDPort*)it->second);
    //create and save the core to bucket mapping
    for(uint16_t i = 0; i < port_->reta_size_; i++) {
      uint16_t core_id = port_->reta_table_[i];
      assert(core_id < total_core_count_);
      if (core_bucket_mapping_.find(core_id) == core_bucket_mapping_.end()) {
        core_bucket_mapping_[core_id] = std::vector<uint16_t>();
      }
      core_bucket_mapping_[core_id].push_back(i);
    }
  }
  std::ifstream file("long_term_threshold");
  while (!file.eof()) {
    uint64_t pps;
    uint64_t flow_count;
    file >> pps;
    file >> flow_count;
    threshold_[flow_count] = pps;
  }
   
   return CommandSuccess();
}
/*
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
*/

std::map<uint16_t, uint16_t> NFVCtrl::findMoves(double flow_rate_per_cpu[], std::vector<uint16_t> to_be_moved, std::vector<double> flow_rate_per_bucket) {
  std::map<uint16_t, uint16_t> moves;
  //if not found return error
  for (auto it: to_be_moved) {
    double flow_rate = flow_rate_per_bucket[it];
    bool found = false;
    for (uint16_t i = 0; i < total_core_count_; i++) {
      if (flow_rate_per_cpu[i] + flow_rate < threshold_[1000]) {
        flow_rate_per_cpu[i] += flow_rate;
        moves[it] = i;
        core_bucket_mapping_[i].push_back(it);
        found = true;
        break;
      }
    }
    if (!found) {
      LOG(INFO) << "Need a new CPU";
    }
  }
  return moves;
}

std::map<uint16_t, uint16_t> NFVCtrl::longTermOptimization(std::vector<double> flow_rate_per_bucket) {
  //compute total flow rate per cpu
  double flow_rate_per_cpu[total_core_count_];
  for (uint16_t i = 0; i < total_core_count_; i++) {
    flow_rate_per_cpu[i] = 0;
    for (auto it: core_bucket_mapping_[i]) {
      flow_rate_per_cpu[i] += flow_rate_per_bucket[it];
    }
  }


  std::vector<uint16_t> to_be_moved;
  // Find if any CPU is exceeding threshold and add it to the to be moved list
  for (uint16_t i = 0; i < total_core_count_; i++) {
    while (flow_rate_per_cpu[i] > threshold_[1000]) {
      //find a bucket to move and do this till all flow rate comes down the threshold
      uint16_t bucket = core_bucket_mapping_[i].back();
      to_be_moved.push_back(bucket);
      core_bucket_mapping_[i].pop_back();
      flow_rate_per_cpu[i] -= flow_rate_per_bucket[bucket];
    }
  }

  //Find a cpu for the buckets to be moved
  // we should pass flow_rate_per_cpu by reference
  std::map<uint16_t, uint16_t> moves = findMoves(flow_rate_per_cpu, to_be_moved, flow_rate_per_bucket);
  for (auto it: moves) {
    flow_rate_per_cpu[it.second] += flow_rate_per_bucket[it.first];
  }
  // Find the CPU with minimum flow rate and delete it
  uint16_t smallest_core = 0;
  double min_flow = flow_rate_per_cpu[0];
  for(uint16_t i = 1; i < total_core_count_; i++) {
    if (flow_rate_per_cpu[i] < min_flow) {
      min_flow = flow_rate_per_cpu[i];
      smallest_core = i;
    }
  }
  LOG(INFO) << "rying to remove: " << smallest_core;
  flow_rate_per_cpu[smallest_core] = threshold_[1000];
  std::map<uint16_t, uint16_t> moves_tmp = findMoves(flow_rate_per_cpu, core_bucket_mapping_[smallest_core], flow_rate_per_bucket);
  moves.insert(moves_tmp.begin(), moves_tmp.end());
  LOG(INFO) << "Total moves: " << moves.size();
  return moves;

}

void NFVCtrl::UpdateFlowAssignment() {
  std::vector<double> flow_rate_per_bucket;
  int i = 0;
  bess::utils::bucket_stats.bucket_table_lock.lock();
  for (i=0; i< RETA_SIZE; i++) {
    flow_rate_per_bucket.push_back(bess::utils::bucket_stats.per_bucket_packet_counter[i]*1000000000/long_epoch_update_period_);
    bess::utils::bucket_stats.per_bucket_packet_counter[i] = 0;
  }
  bess::utils::bucket_stats.bucket_table_lock.unlock();
  
  std::map<uint16_t, uint16_t> moves = longTermOptimization(flow_rate_per_bucket);
  //Create reta table and upadate rss
  for (auto it:moves) {
  LOG(INFO) << it.first << " " << it.second;
  }
  port_->UpdateRssReta(moves);
//  WriteToGurobi(total_core_count_, flow_rate_per_bucket,slo_p50_);
}

void NFVCtrl::DeInit() {
  nfv_ctrl = nullptr;
  NFVCtrlMsgDeInit();
}

CommandResponse NFVCtrl::CommandGetSummary([[maybe_unused]]const bess::pb::EmptyArg &arg) {
  for (const auto &it : ModuleGraph::GetAllModules()) {
    if (it.first.find("nfv_monitor") != std::string::npos) {
      ((NFVMonitor *)(it.second))->CommandGetSummary(arg);
    }
  }
  return CommandSuccess();
}

struct task_result NFVCtrl::RunTask(Context *ctx, bess::PacketBatch *batch, void *) {
  if (tsc_to_ns(rdtsc()) - long_epoch_last_update_time_ > long_epoch_update_period_) {
    UpdateFlowAssignment();
    long_epoch_last_update_time_ = tsc_to_ns(rdtsc());
  }
  RunNextModule(ctx, batch); // To avoid [-Werror=unused-parameter] error
  return {.block = false, .packets = 0, .bits = 0};
}

void NFVCtrl::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  RunNextModule(ctx, batch); // To avoid [-Werror=unused-parameter] error
}

ADD_MODULE(NFVCtrl, "nfv_ctrl", "The per-worker NFV controller that interacts with NFVCore and NFVMonitor")
