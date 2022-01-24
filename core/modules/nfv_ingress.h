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
    };

    int core_id;
    int worker_port;
    std::string nic_addr;
    std::unordered_map<Flow, uint64_t, FlowHash> active_flows;
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
  void default_lb(); // default lb op = 0 (round-robin)
  void traffic_aware_lb(); // lb op = 1 (traffic-awareness)

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

  // LB and scaling options
  int load_balancing_op_ = 0;
  int scale_op_ = 0;

  // All available per-core packet queues in a cluster
  std::vector<WorkerCore> cpu_cores_;
  std::unordered_map<std::string, int> routing_to_core_id_;

  std::vector<int> idle_cores_;
  std::vector<int> normal_cores_;
  // The number of normal / reserved CPU cores
  int total_core_count_ = 0;
  int normal_core_count_ = 0;
  int idle_core_count_ = 0;
  // The selected normal / reserved CPU core
  int next_normal_core_ = 0;
  int next_idle_core_ = 0;
  int rr_normal_core_index_ = 0;

  // Packet rate threshold for identifying high-rate flows
  uint64_t packet_count_thresh_;

  // Per-flow connection table
  std::unordered_map<Flow, FlowRoutingRule, FlowHash> flow_cache_;

  // Total number of active flows in the flow cache
  int active_flows_ = 0;
};

#endif // BESS_MODULES_NFV_INGRESS_H_
