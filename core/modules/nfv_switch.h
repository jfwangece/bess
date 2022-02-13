#ifndef BESS_MODULES_NFV_SWITCH_H_
#define BESS_MODULES_NFV_SWITCH_H_

#include <map>
#include <set>
#include <vector>

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/flow.h"
#include "../utils/ip.h"
#include "../utils/sys_measure.h"

using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Ipv4Prefix;
using bess::utils::Flow;
using bess::utils::FlowHash;
using bess::utils::FlowRecord;
using bess::utils::FlowRoutingRule;
using bess::utils::Snapshot;
using bess::utils::CoreStats;

class NFVSwitch final : public Module {
 public:
  static const gate_idx_t kNumOGates = MAX_GATES;

  static const Commands cmds;

  // This struct represents an active worker core
  // |core_id|: the unique CPU core ID number
  // |worker_port|, |nic_addr|: routing information
  // |active_flows|: a set of active flows assigned to this core
  struct WorkerCore {
    WorkerCore() = default;
    WorkerCore(int core, int port, std::string addr) {
      core_id = core; worker_port = port; nic_addr = addr;
      active_flow_count = 0; packet_rate = 0; idle_period_count = 0;
    };

    // CPU core info
    int core_id;
    int worker_port;
    std::string nic_addr;

    // Traffic or performance statistics
    int active_flow_count;
    float packet_rate;
    uint64_t p99_latency;
    int idle_period_count;

    // Timestamp
    uint64_t last_migrating_ts_ns_;
  };

  NFVSwitch() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const bess::pb::NFVSwitchArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);
  CommandResponse CommandGetSummary(const bess::pb::EmptyArg &arg);

 private:
  // Modify |rule| to assign a new flow to an active core
  bool process_new_flow(FlowRoutingRule &rule);

  void pick_next_normal_core(); // Assign a normal flow to a normal core
  void pick_next_idle_core(); // Assign a bursty flow to an reserved core

  // default (round-robin), lb op = 0
  void default_lb();

  // Quadrant's algorithm, lb op = 1 (greedy packing)
  void quadrant_lb() {}
  void quadrant_migrate() {}
  int quadrant_pick_core() { return 0; } // pick the core with the highest-rate within the assignment thresh

  // New, lb op = 2 (traffic-awareness)
  void traffic_aware_lb();

  // To update flow routing and per-flow counters
  void migrate_flow(const Flow &f, int from_cid, int to_cid);

  // This function collects per-core performance statistics from
  // each core's ll_ring channel.
  // Return true if this module successfully updates traffic statistics;
  // Otherwise, return false.
  bool update_traffic_stats();

  bool is_idle_core(int core_id) {
    for (auto &it : idle_cores_) {
      if (it == core_id) { return true; }
    }
    return false;
  }
  bool is_normal_core(int core_id) {
    for (auto &it : normal_cores_) {
      if (it == core_id) { return true; }
    }
    return false;
  }
  void log_core_info() {
    LOG(INFO) << "Idle cores:";
    for (auto &it : idle_cores_) {
      LOG(INFO) << it;
    }
    LOG(INFO) << "Normal cores:";
    for (auto &it : normal_cores_) {
      LOG(INFO) << it;
    }
  }

  // Timestamp
  uint64_t curr_ts_ns_;
  uint64_t last_core_assignment_ts_ns_;
  uint64_t last_update_traffic_stats_ts_ns_;
  uint64_t update_traffic_stats_period_ns_;
  int next_epoch_id_; // Performance statistics recorded in Epoch

  // LB and scaling options
  int load_balancing_op_ = 0;
  int scale_op_ = 0;

  // All available per-core packet queues in a cluster
  std::vector<WorkerCore> cpu_cores_;
  std::unordered_map<std::string, int> routing_to_core_id_;

  std::vector<Snapshot> cluster_snapshots_;

  std::vector<int> idle_cores_;
  std::vector<int> normal_cores_;

  // The number of normal / reserved CPU cores
  // |normal_core_count_| + |idle_core_count_| <= |total_core_count_|
  int total_core_count_ = 0;
  int normal_core_count_ = 0;
  int idle_core_count_ = 0;

  // The selected normal / reserved CPU core
  int next_normal_core_ = 0;
  int next_idle_core_ = 0;
  int rr_normal_core_index_ = 0;
  int rr_idle_core_index_ = 0;

  // Packet rate threshold for identifying high-rate flows
  uint64_t packet_count_thresh_;

  // Quadrant parameters
  uint64_t quadrant_per_core_packet_rate_thresh_;
  float quadrant_low_thresh_;
  float quadrant_target_thresh_;
  float quadrant_high_thresh_;
  float quadrant_assign_packet_rate_thresh_; // stop assigning more flows
  float quadrant_migrate_packet_rate_thresh_; // start migrating flows

  // Traffic-aware parameters
  int ta_flow_count_thresh_; // Stop assigning more flows

  // Per-flow connection table
  std::unordered_map<Flow, FlowRoutingRule, FlowHash> flow_cache_;

  // Total number of active flows in the flow cache
  int active_flows_ = 0;
};

#endif // BESS_MODULES_NFV_SWITCH_H_
