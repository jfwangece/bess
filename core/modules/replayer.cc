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
  playback_rate_mpps_ = 0.0;
  if (arg.rate_mpps() > 0) {
    playback_rate_mpps_ = arg.rate_mpps();
  }
  playback_rate_mbps_ = 0.0;
  if (arg.rate_mbps() > 0) {
    playback_rate_mbps_ = arg.rate_mbps();
  }

  use_trace_time_ = !(playback_rate_mpps_ > 0 || playback_rate_mbps_ > 0);

  use_batching_ = true;
  if (arg.use_batching() == false) {
    use_batching_ = false;
  }

  temp_pkt_cnt_ = 0;
  temp_bit_cnt_ = 0;
  // Record the startup timestamp. Note: this module starts to send packets after 1 sec
  if (use_trace_time_) {
    curr_time_ = tsc_to_us(rdtsc());
    startup_ts_ = tsc_to_us(rdtsc()) + 2000000;
  } else {
    curr_time_ = tsc_to_ns(rdtsc());
    startup_ts_ = tsc_to_us(rdtsc()) + 2000000000;
  }
  last_rate_calc_ts_ = startup_ts_;
  next_pkt_time_ = startup_ts_;

  return CommandSuccess();
}

void Replayer::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();

  if (use_batching_) { // batching
    WaitToSendPkt(batch->pkts()[cnt-1]);

    if (playback_rate_mpps_ > 0) {
      // Replay at a certain packet rate
      next_pkt_time_ = curr_time_ + cnt * 1000 / playback_rate_mpps_;
    } else if (playback_rate_mbps_ > 0) {
      // Replay at a certain bit rate
      uint64_t sum_bytes = 0;
      for (int i = 0; i < cnt; i++) {
        sum_bytes += batch->pkts()[i]->total_len();
      }
      next_pkt_time_ = curr_time_ + sum_bytes * 8000 / playback_rate_mbps_;
    }

    RunNextModule(ctx, batch);
  } else { // non batching
    for (int i = 0; i < cnt; i++) {
      // A busy loop that sends a packet until the current time passes the packet's time.
      WaitToSendPkt(batch->pkts()[i]);

      EmitPacket(ctx, batch->pkts()[i], 0);
      temp_pkt_cnt_ += 1;
      temp_bit_cnt_ += batch->pkts()[i]->total_len() * 8;

      if (playback_rate_mpps_ > 0) {
        // Replay at a certain packet rate
        next_pkt_time_ = curr_time_ + 1000 / playback_rate_mpps_;
      } else if (playback_rate_mbps_ > 0) {
        // Replay at a certain bit rate
        next_pkt_time_ = curr_time_ + batch->pkts()[i]->total_len() * 8000 / playback_rate_mbps_;
      }
    }
  }
}

// Return when the current time exceeds |pkt|'s departure time.
// Note: if |use_trace_time_|, then it should first read the packet's departure time
// from the packet's payload.
void Replayer::WaitToSendPkt(bess::Packet *pkt) {
  uint64_t time_diff = 0;
  if (use_trace_time_) {
      // Read the timestamp in the TCP header.
      GetTimestamp(pkt, offset_, &time_diff);

      if (time_diff) {
        if (time_diff > 60000000) {
          time_diff = 0;
        }
        if (playback_speed_ >= 0.1) {
          time_diff /= playback_speed_;
        }
      }
      next_pkt_time_ = startup_ts_ + time_diff;
    }

// Emit a packet only if |curr_time_| passes the calculated packet timestamp
checktime:
    if (use_trace_time_) {
      curr_time_ = tsc_to_us(rdtsc());
    } else {
      curr_time_ = tsc_to_ns(rdtsc());
    }

    if (curr_time_ > next_pkt_time_) {
      return;
    } else {
      goto checktime;
    }
}

ADD_MODULE(Replayer, "replayer",
           "Replay a pcap packet trace that keeps the original traffic dynamics")
