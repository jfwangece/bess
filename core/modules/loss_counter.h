#ifndef BESS_MODULES_LOSS_COUNTER_H_
#define BESS_MODULES_LOSS_COUNTER_H_

#include <mutex>
#include <set>

#include "../module.h"
#include "../utils/endian.h"
#include "../utils/mcslock.h"

struct PerPortCounter {
  PerPortCounter() = default;

  uint64_t CountPerPortLosses() { return (egress_cnt - ingress_cnt); }

  void Clear() { is_counting_ = false; egress_cnt = 0; ingress_cnt = 0; }

  void Start() {
    egress_cnt = 0;
    ingress_cnt = 0;
    is_counting_ = true;
  }

  // If true, mark all egress packets as countable packets.
  bool is_counting_ = false;

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

  // global packet counters
  static PerPortCounter per_port_counters_[64];
  static std::set<int> all_ports_;

  // global lock for updating global packet counters
  static mcslock lock_;
  static std::mutex mu_;

  static const Commands cmds;

  CommandResponse Init(const bess::pb::LossCounterArg &arg);
  CommandResponse CommandGetSummary(
      const bess::pb::LossCounterCommandGetSummaryArg &arg);
  CommandResponse CommandClear(const bess::pb::EmptyArg &);
  CommandResponse CommandStart(const bess::pb::LossCounterStartArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;
  void Activate() { is_activated_ = false; }
  void Clear();
  void Start();

private:
  uint64_t CountTotalLosses();
  uint64_t CountTotalPackets();

  // The current global tsc.
  uint64_t now_;
  size_t offset_;

  static bool is_activated_;

  // At runtime, a per-port counter starts counting after its egress
  // counter hits |packet_count_offset_|, and stops after its egress
  // counter hits |packet_count_target_|.
  static uint64_t packet_count_offset_;
  static uint64_t packet_count_target_;

  // The ingress/egress port at which this instance is monitoring.
  int port_index_ = 0;
  PortType port_type_ = kEgress;
};

#endif // BESS_MODULES_LOSS_COUNTER_H_
