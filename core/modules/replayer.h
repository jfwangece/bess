#ifndef BESS_MODULES_REPLAYER_H_
#define BESS_MODULES_REPLAYER_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"

#include <vector>

class Replayer final : public Module {
 public:
  Replayer() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const bess::pb::ReplayerArg &arg);
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;
  void WaitToSendPkt(bess::Packet *pkt);
  void UpdateDynamicPlaybackSpeed();

 private:
  // The offset / attribute ID of the per-packet timestamp
  size_t offset_;

  // Playback parameters:
  bool use_trace_time_;
  bool use_batching_;

  // |playback_speed_| accelerates the trace to speed up the packet rate;
  // |playback_rate_| tunes to |playback_speed_| dynamically so that the
  // actual packet rate matches the |playback_rate_|. If zero, no effect.
  double playback_speed_ = 1.0;
  double playback_rate_mpps_ = 0.0;
  double playback_rate_mbps_ = 0.0;

  // |dynamic_traffic_conf_| specifies how traffic changes
  // dynamically in time (in 200-ms time granularity).
  std::vector<double> dynamic_speed_conf_;
  uint64_t last_dynamic_speed_idx_;
  uint64_t last_dynamic_speed_ts_;

  // Timestamp info
  uint64_t last_pkt_ts_; // The last packet arrival's timestamp
  uint64_t curr_ts_; // The system's current timestamp (updated per packet batch)
  uint64_t next_pkt_time_; // The calculated timestamp for generating the next packet

  // for packet rate calculation
  uint64_t temp_pkt_cnt_;
  uint64_t temp_bit_cnt_;
  uint64_t last_rate_calc_ts_;
  double temp_rate_mpps_;
  double temp_rate_mbps_;
};

#endif // BESS_MODULES_REPLAYER_H_
