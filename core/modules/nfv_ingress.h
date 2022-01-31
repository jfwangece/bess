#ifndef BESS_MODULES_NFV_INGRESS_H_
#define BESS_MODULES_NFV_INGRESS_H_

#include <map>
#include <set>
#include <vector>

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/flow.h"
#include "../utils/ip.h"

using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Ipv4Prefix;
using bess::utils::Flow;
using bess::utils::FlowHash;
using bess::utils::FlowRecord;
using bess::utils::FlowRoutingRule;

class NFVIngress final : public Module {
 public:
  static const Commands cmds;

  // This struct represents an active worker core
  // |core_id|: the unique CPU core ID number
  // |worker_port|, |nic_addr|: routing information
  // |active_flows|: a set of active flows assigned to this core
  struct WorkerCore {
    WorkerCore(int core, int port, std::string addr) {
      core_id = core; worker_port = port; nic_addr = addr;
      active_flow_count = 0; packet_rate = 0; idle_period_count = 0;
      per_flow_packet_counter.clear();
    };

    // Core info
    int core_id;
    int worker_port;
    std::string nic_addr;
    // Traffic statistics
    int active_flow_count;
    uint64_t packet_rate;
    int idle_period_count;
    // Timestamp
    uint64_t last_migrating_ts_ns_;
    // Flow statistics
    std::unordered_map<Flow, uint64_t, FlowHash> per_flow_packet_counter;
  };

  struct Snapshot {
    Snapshot(int t_id) {
      epoch_id = t_id; active_core_count = 0; sum_packet_rate = 0;
    };

    int epoch_id; // Starting from 0
    int active_core_count; // Number of CPU cores with traffic
    uint64_t sum_packet_rate; // Sum of all CPU cores' packet rates
    std::vector<uint64_t> per_core_packet_rate;
  };

  NFVIngress() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const bess::pb::NFVIngressArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse CommandAdd(const bess::pb::NFVIngressArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);
  CommandResponse CommandGetSummary(const bess::pb::EmptyArg &arg);

 private:
  // Modify |rule| to assign a new flow to an active core
  bool process_new_flow(FlowRoutingRule &rule);

  void pick_next_normal_core(); // Assign a normal flow to a normal core
  void pick_next_idle_core(); // Assign a bursty flow to an reserved core

  // default (round-robin), lb op = -1
  void default_lb();

  // Quadrant's algorithm, lb op = 0 (greedy packing)
  void quadrant_lb();
  void quadrant_migrate();
  int quadrant_pick_core(); // pick the core with the highest-rate within the assignment thresh

  // New, lb op = 1 (traffic-awareness)
  void traffic_aware_lb();

  // To update flow routing and per-flow counters
  void migrate_flow(const Flow &f, int from_cid, int to_cid);

  // Remove inactive flows every |traffic-stats-update| period
  void update_traffic_stats();

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
    std::cout << "Idle cores:";
    for (auto &it : idle_cores_) {
      std::cout << it;
    }
    std::cout << "Normal cores:";
    for (auto &it : normal_cores_) {
      std::cout << it;
    }
  }

  // Timestamp
  uint64_t curr_ts_ns_;
  uint64_t last_core_assignment_ts_ns_;
  uint64_t last_update_traffic_stats_ts_ns_;
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

  uint64_t quadrant_per_core_packet_rate_thresh_;
  double quadrant_low_thresh_;
  double quadrant_target_thresh_;
  double quadrant_high_thresh_;
  uint64_t quadrant_assign_packet_rate_thresh_; // stop assigning more flows
  uint64_t quadrant_migrate_packet_rate_thresh_; // start migrating flows

  // Per-flow connection table
  std::unordered_map<Flow, FlowRoutingRule, FlowHash> flow_cache_;

  // Total number of active flows in the flow cache
  int active_flows_ = 0;
};

#endif // BESS_MODULES_NFV_INGRESS_H_
