#ifndef BESS_MODULES_LOSS_COUNTER_H_
#define BESS_MODULES_LOSS_COUNTER_H_

#include <set>

#include "../module.h"
#include "../utils/endian.h"
#include "../utils/mcslock.h"

struct PerPortCounter {
  PerPortCounter() = default;
  uint64_t CountPerPortLosses() { return (egress_cnt - ingress_cnt); }
  void Clear() { egress_cnt = 0; ingress_cnt = 0; }

  // TrafficGen egress
  uint64_t egress_cnt = 0;
  // TrafficGen ingress
  uint64_t ingress_cnt = 0;
};


class LossCounter final: public Module {
public:
  enum PortType {
    kEgress = 0,
    kIngress,
  };

  static PerPortCounter per_port_counters_[64];
  static std::set<int> all_ports_;

  static const Commands cmds;

  CommandResponse Init(const bess::pb::LossCounterArg &arg);
  CommandResponse CommandGetSummary(
      const bess::pb::LossCounterCommandGetSummaryArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &);
  CommandResponse CommandStart(const bess::pb::LossCounterStartArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;
  void Activate() { activated_ = true; }
  void Clear();
  void Start();

private:
  uint64_t CountTotalLosses();
  uint64_t CountTotalPackets();

  // The current global tsc.
  uint64_t now_;

  static bool activated_;
  static uint64_t target_packet_count_;

  // The ingress/egress port at which this instance is monitoring.
  int port_index_ = 0;
  PortType port_type_ = kEgress;

  static mcslock lock_;
};

#endif // BESS_MODULES_LOSS_COUNTER_H_
