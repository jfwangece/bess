#include "replayer.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/time.h"
#include "../utils/udp.h"

namespace {
#define kDefaultTagOffset 64
#define kDefaultRateCalcPeriodUs 100000

void GetTimestamp(bess::Packet *pkt, size_t offset, uint64_t *time) {
  *time = *(pkt->head_data<uint64_t *>(offset));
}
}

CommandResponse Replayer::Init(const bess::pb::ReplayerArg &arg) {
  if (arg.offset()) {
    offset_ = arg.offset();
  } else {
    offset_ = kDefaultTagOffset;
  }
  playback_speed_ = 1.0;
  if (arg.speed() >= 0.5) {
    playback_speed_ = arg.speed();
  }
  playback_rate_mpps_ = 0.8;
  if (arg.rate_mpps() > 0) {
    playback_rate_mpps_ = arg.rate_mpps();
  }
  playback_rate_mbps_ = 0.0;
  if (arg.rate_mbps() > 0) {
    playback_rate_mbps_ = arg.rate_mbps();
  }

  // Record the startup timestamp
  startup_ts_ = tsc_to_us(rdtsc());
  temp_pkt_cnt_ = 0;
  last_rate_calc_ts_ = startup_ts_;

  return CommandSuccess();
}

void Replayer::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  // uint64_t now_us = tsc_to_us(rdtsc());
  // Read the timestamp in the TCP header.
  uint64_t curr_time, pkt_time = 0;
  double time_diff;
  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    pkt_time = 0;
    GetTimestamp(batch->pkts()[i], offset_, &pkt_time);

    if (pkt_time) {
      if (playback_speed_ >= 0.1) {
        pkt_time /= playback_speed_;
      }
checktime:
      curr_time = tsc_to_us(rdtsc());

      // Calculate packet rate and update the playback speed if necessary
      time_diff = curr_time - last_rate_calc_ts_;
      if (time_diff > kDefaultRateCalcPeriodUs) {
        temp_rate_mpps_ = (double)temp_pkt_cnt_ / time_diff;
        temp_pkt_cnt_ = 1;
        last_rate_calc_ts_ = curr_time;

        if (playback_rate_mpps_ > 0) {
          playback_speed_ = playback_rate_mpps_ / temp_rate_mpps_;
        }
        std::cout << playback_rate_mpps_ << temp_rate_mpps_ << playback_speed_;
      }

      if (curr_time > startup_ts_ + pkt_time) {
        EmitPacket(ctx, batch->pkts()[i], 0);
        temp_pkt_cnt_ += 1;
      } else {
        goto checktime;
      }
    }
  }
}

ADD_MODULE(Replayer, "replayer",
           "Replay a pcap packet trace that keeps the original traffic dynamics")
