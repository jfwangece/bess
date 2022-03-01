#ifndef BESS_MODULES_NFV_CORE_H_
#define BESS_MODULES_NFV_CORE_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/flow.h"
#include "../utils/ip.h"
#include "../utils/sys_measure.h"

using bess::utils::Flow;
using bess::utils::FlowHash;
using bess::utils::FlowRoutingRule;
using bess::utils::CoreStats;
using bess::utils::WorkerCore;

class NFVCore final : public Module {
 public:
  static const Commands cmds;

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

  NFVCore() : Module() { max_allowed_workers_ = 1; }

  CommandResponse Init(const bess::pb::NFVCoreArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  CommandResponse CommandClear(const bess::pb::EmptyArg &arg);

  bool update_traffic_stats();

 private:
  int core_id_;
  WorkerCore core_;

  uint64_t curr_ts_ns_;

  // Max number of new flows processed in a epoch
  uint32_t epoch_packet_thresh_;
  uint32_t epoch_flow_thresh_;
  uint32_t epoch_packet_counter_;

  // Flow cache
  std::unordered_map<Flow, bool, FlowHash> epoch_flow_cache_;
  std::unordered_map<Flow, uint32_t, FlowHash> per_flow_packet_counter_;
};

#endif // BESS_MODULES_NFV_CORE_H_
