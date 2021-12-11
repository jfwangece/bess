#ifndef BESS_MODULES_REPLAYER_H_
#define BESS_MODULES_REPLAYER_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"

class Replayer final : public Module {
 public:
  Replayer() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const bess::pb::ReplayerArg &arg);
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

 private:
  // The offset / attribute ID of the per-packet timestamp
  size_t offset_;
  // Playback parameters:
  bool use_trace_time_;
  // |playback_speed_| accelerates the trace to speed up the packet rate;
  // |playback_rate_| tunes to |playback_speed_| dynamically so that the
  // actual packet rate matches the |playback_rate_|. If zero, no effect.
  double playback_speed_ = 1.0;
  double playback_rate_mpps_ = 0.0;
  double playback_rate_mbps_ = 0.0;
  // Startup timestmap
  uint64_t startup_ts_;
  // for packet rate calculation
  uint64_t temp_pkt_cnt_;
  uint64_t temp_bit_cnt_;
  uint64_t last_rate_calc_ts_;
  double temp_rate_mpps_;
  double temp_rate_mbps_;
  // Timestamp info
  uint64_t curr_time_;
  uint64_t next_pkt_time_;
};

#endif // BESS_MODULES_REPLAYER_H_
