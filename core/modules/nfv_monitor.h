#ifndef BESS_MODULES_NFV_MONITOR_H_
#define BESS_MODULES_NFV_MONITOR_H_

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

class NFVMonitor final : public Module {
 public:
  static const Commands cmds;

  struct Snapshot {
    Snapshot(int t_id) {
      epoch_id = t_id; active_core_count = 0; sum_packet_rate = 0;
    };

    int epoch_id; // Starting from 0
    int active_core_count; // Number of CPU cores with traffic
    uint64_t sum_packet_rate; // Sum of all CPU cores' packet rates
    std::vector<uint64_t> per_core_packet_rate;
  };

  NFVMonitor() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const bess::pb::NFVMonitorArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse CommandAdd(const bess::pb::NFVMonitorArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);
  CommandResponse CommandGetSummary(const bess::pb::EmptyArg &arg);

 private:
  bool update_traffic_stats();

  // Timestamp
  uint64_t curr_ts_ns_;
  uint64_t last_update_traffic_stats_ts_ns_;
  uint64_t update_traffic_stats_period_ns_;
  int next_epoch_id_; // Performance statistics recorded in Epoch

  // Cluster statistics
  std::vector<Snapshot> cluster_snapshots_;

  // Flow statistics
  std::unordered_map<Flow, uint64_t, FlowHash> per_flow_packet_counter_;

  // Traffic summary
  int active_flow_count_;
  float packet_rate_;
  int idle_period_count_;

  int core_id_;
};

#endif // BESS_MODULES_NFV_MONITOR_H_
