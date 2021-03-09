#ifndef BESS_MODULES_FlowLimiter_H_
#define BESS_MODULES_FlowLimiter_H_

#include <map>

#include "../module.h"
#include "../utils/endian.h"
#include "../utils/mcslock.h"

using bess::utils::be32_t;
using bess::utils::be16_t;

class FlowLimiter final: public Module {
public:
  typedef std::tuple<be32_t, be32_t, uint8_t, be16_t, be16_t> FlowTuple;
  struct PerFlowCounter {
    PerFlowCounter() = default;
    PerFlowCounter(uint64_t cnt, uint64_t tsc): pkt_cnt(cnt), last_pkt_tsc(tsc) {};

    uint64_t pkt_cnt;
    uint64_t last_pkt_tsc;
  };

  CommandResponse Init(const bess::pb::FlowLimiterArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

private:
  std::map<FlowTuple, PerFlowCounter> map_flow_to_counter_;
  FlowTuple new_flow_;

  // The number of new flows in a measurement duration.
  uint32_t count_new_flows_ = 0;
  uint32_t num_flows_ = 0;

  mcslock lock_;
};

#endif // BESS_MODULES_FlowLimiter_H_
