#ifndef BESS_MODULES_NFV_MONITOR_H_
#define BESS_MODULES_NFV_MONITOR_H_

#include <boost/circular_buffer.hpp>
#include <math.h>
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
using bess::utils::CoreSnapshot;

class NFVMonitor final : public Module {
 public:
  static const Commands cmds;

  NFVMonitor() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const bess::pb::NFVMonitorArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);
  CommandResponse CommandGetSummary(const bess::pb::EmptyArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  uint64_t GetTailLatency(uint32_t percentile) {
    std::vector<uint64_t> latency_copy;
    // Create a copy of the latency buffer
    for (auto it = per_core_latency_sample_.begin(); it != per_core_latency_sample_.end(); it++) {
      latency_copy.push_back(*it);
    }
    sort(latency_copy.begin(), latency_copy.end());
    size_t idx = ceil((percentile / 100.0) * latency_copy.size());
    return latency_copy[idx];
  }

 private:
  bool update_traffic_stats();

  // Timestamp
  uint64_t curr_ts_ns_;
  uint64_t curr_nic_ts_ns_;
  uint64_t last_update_traffic_stats_ts_ns_;
  uint64_t update_traffic_stats_period_ns_;

  int next_epoch_id_; // Performance statistics recorded in Epoch

  // Core statistics
  std::vector<CoreSnapshot> core_snapshots_;

  // Flow statistics
  std::unordered_map<Flow, uint32_t, FlowHash> per_flow_packet_counter_;

  // Core statistics
  boost::circular_buffer<uint64_t> per_core_latency_sample_;
  uint16_t epoch_packet_counter_;
  uint16_t epoch_queue_length_;
  uint16_t epoch_slo_violation_counter_;
  uint16_t epoch_packet_delay_error_;
  uint16_t epoch_packet_delay_max_;

  // Once a flow's packet counter exceeds this thresh, it is a bursty flow.
  uint16_t epoch_packet_thresh_;

  // Traffic summary
  int active_flow_count_;
  float packet_rate_;
  int idle_period_count_;
  int core_id_;
};

#endif // BESS_MODULES_NFV_MONITOR_H_
