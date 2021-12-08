#ifndef BESS_MODULES_FLOWSTATS_H_
#define BESS_MODULES_FLOWSTATS_H_

#include <map>

#include "../module.h"
#include "../utils/endian.h"
#include "../utils/mcslock.h"

using bess::utils::be32_t;
using bess::utils::be16_t;

class FlowStats final: public Module {
public:
  typedef std::tuple<be32_t, be32_t, uint8_t, be16_t, be16_t> FlowTuple;
  struct PerFlowCounter {
    PerFlowCounter() = default;
    PerFlowCounter(uint64_t cnt, uint64_t tsc): pkt_cnt(cnt), last_pkt_tsc(tsc) {
      temp_pkt_cnt = 1;
    };

    uint64_t pkt_cnt;
    uint64_t temp_pkt_cnt;
    uint64_t last_pkt_tsc;
  };

  static const Commands cmds;

  CommandResponse Init(const bess::pb::FlowStatsArg &arg);
  CommandResponse CommandGetSummary(
      const bess::pb::FlowStatsCommandGetSummaryArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &);

  uint32_t CountActiveFlows(const uint64_t& tsc);
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;
  void Clear();

private:
  std::map<FlowTuple, PerFlowCounter> map_flow_to_counter_;
  FlowTuple new_flow_;

  // The number of new flows in a measurement duration.
  uint32_t count_new_flows_ = 0;

  // The current flow arrival rate.
  double flow_arrival_rate_ = 0;
  double peak_flow_arrival_rate_ = 0;
  double peak_per_flow_pkt_rate_ = 0;

  // The current number of active flows.
  uint32_t active_flows_ = 0;
  uint32_t peak_active_flows_ = 0;

  uint64_t flow_timeout_tsc_;
  uint64_t flow_entry_timeout_tsc_;
  uint64_t measure_period_tsc_;
  uint64_t last_measure_tsc_;

  mcslock lock_;
};

#endif // BESS_MODULES_FLOWSTATS_H_
