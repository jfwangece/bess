#ifndef BESS_MODULES_FAAS_EMULATOR_H_
#define BESS_MODULES_FAAS_EMULATOR_H_

#include <map>

#include "../module.h"
#include "../utils/endian.h"
#include "../utils/mcslock.h"

using bess::utils::be32_t;
using bess::utils::be16_t;

class FaaSController final: public Module {
public:
  typedef std::tuple<be32_t, be32_t> L3FlowTuple;
  typedef std::tuple<be32_t, be32_t, uint8_t, be16_t, be16_t> FlowTuple;

  struct PerFlowCounter {
    PerFlowCounter() = default;
    PerFlowCounter(uint64_t cnt, uint64_t tsc): pkt_cnt(cnt), last_pkt_tsc(tsc) {
      last_calc_pkt_cnt = cnt;
      last_calc_tsc = tsc;
      flow_rate_kpps = 0;
    };

    uint64_t pkt_cnt;
    uint64_t last_pkt_tsc;
    uint64_t last_calc_pkt_cnt; // for rate calculation
    uint64_t last_calc_tsc; // for rate calculation
    double flow_rate_kpps;
    uint32_t core_id;
  };
  struct CoreInfo {
    CoreInfo(): is_active(false), total_pkt_rate(0) {};
    bool is_active;
    double total_pkt_rate;
  };

  static const Commands cmds;

  CommandResponse Init(const bess::pb::FaaSControllerArg &arg);
  CommandResponse CommandGetSummary(
      const bess::pb::FaaSControllerCommandGetSummaryArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &);

  std::string GetDesc() const override;

  uint32_t UpdateFlowInfo(const uint64_t& tsc);
  uint32_t UpdateCoreInfo();
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;
  void Clear();

private:
  std::map<FlowTuple, PerFlowCounter> map_flow_to_counter_;
  std::map<L3FlowTuple, PerFlowCounter> map_l3flow_to_counter_;
  std::map<uint32_t, CoreInfo> map_coreinfo_;

  FlowTuple new_flow_;
  L3FlowTuple new_l3flow_;

  // The number of new flows in a measurement duration.
  uint32_t count_new_flows_ = 0;

  // The current flow arrival rate.
  double flow_arrival_rate_ = 0;
  double peak_flow_arrival_rate_ = 0;

  // The current number of active flows.
  uint32_t active_flows_ = 0;
  uint32_t active_cores_ = 0;
  double last_avg_cores_ = 0;
  double sum_core_time_ = 0;
  double sum_running_time_ = 0;
  uint32_t peak_active_flows_ = 0;

  uint32_t max_per_core_kpps_ = 1000;
  uint32_t curr_target_core_ = 0;

  uint64_t flow_timeout_tsc_;
  uint64_t flow_entry_timeout_tsc_;
  uint64_t rate_calc_period_tsc_;
  uint64_t update_cluster_period_tsc_;
  uint64_t last_update_cluster_tsc_;

  mcslock lock_;
};

#endif // BESS_MODULES_FAAS_EMULATOR_H_
