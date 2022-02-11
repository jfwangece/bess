#ifndef BESS_MODULES_NFV_MONITOR_H_
#define BESS_MODULES_NFV_MONITOR_H_

#include <math.h>
#include <map>
#include <set>
#include <vector>

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/flow.h"
#include "../utils/ip.h"
#include "../utils/sys_measure.h"
#include <boost/circular_buffer.hpp>

using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Ipv4Prefix;
using bess::utils::Flow;
using bess::utils::FlowHash;
using bess::utils::FlowRecord;
using bess::utils::FlowRoutingRule;
using bess::utils::Snapshot;

class NFVMonitor final : public Module {
 public:
  static const Commands cmds;

  NFVMonitor() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const bess::pb::NFVMonitorArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse CommandAdd(const bess::pb::NFVMonitorArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);
  CommandResponse CommandGetSummary(const bess::pb::EmptyArg &arg);

  double GetTailLatency() {
    std::vector<uint64_t> latency_copy_(per_core_latency_sample_.size());
    // Create a copy of the latency buffer
    for (auto it = per_core_latency_sample_.begin(); it != per_core_latency_sample_.end(); it++) {
      latency_copy_.push_back(*it);
    }
    sort(latency_copy_.begin(), latency_copy_.end());
    size_t idx = ceil(0.99 * latency_copy_.size());
    return latency_copy_[idx];
  }

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

  // Core statistics
  boost::circular_buffer<uint64_t> per_core_latency_sample_;
  uint64_t per_core_packet_counter_;

  // Traffic summary
  int active_flow_count_;
  float packet_rate_;
  int idle_period_count_;

  int core_id_;
};

#endif // BESS_MODULES_NFV_MONITOR_H_