#include "replayer.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/time.h"
#include "../utils/packet_tag.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::GetPacketTimestamp;

namespace {
#define kDefaultTagOffset 64
#define kDefaultRateCalcPeriodUs 100000
#define kMinPlaybackSpeed 0.1
}

CommandResponse Replayer::Init(const bess::pb::ReplayerArg &arg) {
  if (arg.offset()) {
    offset_ = arg.offset();
  } else {
    offset_ = kDefaultTagOffset;
  }

  if (arg.dynamic_traffic_conf().length() > 0) {
    std::string traffic_conf_fname = arg.dynamic_traffic_conf();
    std::ifstream traffic_conf_file(traffic_conf_fname, std::ifstream::in);
    if (traffic_conf_file.is_open()) {
      uint64_t prev_ts = 0;
      double prev_speed = 0;
      uint64_t next_ts = 0;
      double next_speed = 0;
      while (!traffic_conf_file.eof()) {
        traffic_conf_file >> next_ts;
        traffic_conf_file >> next_speed;
        int steps = (next_ts - prev_ts) * 5; // 200 ms per update
        for (int i = 0; i < steps; i++) {
          double curr_speed =
            prev_speed + double(i) * (next_speed - prev_speed) / steps;
          dynamic_speed_conf_.push_back(curr_speed);
        }
        prev_ts = next_ts;
        prev_speed = next_speed;
      }
      dynamic_speed_conf_.push_back(0);
      traffic_conf_file.close();
      LOG(INFO) << "Dynamic traffic conf: " + traffic_conf_fname;

      std::ofstream output;
      output.open("/tmp/traffic.conf");
      for (uint32_t r = 0; r < dynamic_speed_conf_.size(); r++) {
        output << dynamic_speed_conf_[r] << " ";
      }
      output.close();
    } else {
      LOG(INFO) << "Failed to read " + traffic_conf_fname;
    }
  }

  playback_speed_ = 1.0;
  playback_rate_mpps_ = 0.0;
  playback_rate_mbps_ = 0.0;
  if (dynamic_speed_conf_.size()) {
    if (arg.speed() >= 0.5) {
      playback_speed_ = arg.speed();
    }
    if (arg.rate_mpps() > 0) {
      playback_rate_mpps_ = arg.rate_mpps();
    }
    if (arg.rate_mbps() > 0) {
      playback_rate_mbps_ = arg.rate_mbps();
    }
  }

  use_trace_time_ = !(playback_rate_mpps_ > 0 || playback_rate_mbps_ > 0);

  use_batching_ = true;
  if (arg.use_batching() == false) {
    use_batching_ = false;
  }

  temp_pkt_cnt_ = 0;
  temp_bit_cnt_ = 0;
  // Record the startup timestamp.
  // Note: this module starts to send packets after 2 sec
  curr_ts_ = tsc_to_ns(rdtsc());
  startup_ts_ = tsc_to_ns(rdtsc()) + 2000000000;
  last_rate_calc_ts_ = startup_ts_;
  next_pkt_time_ = startup_ts_;

  if (dynamic_speed_conf_.size() > 0) {
    last_dynamic_speed_idx_ = 1;
    playback_speed_ = dynamic_speed_conf_[1];
    last_dynamic_speed_ts_ = curr_ts_;
  }

  // CPU freq in GHz
  LOG(INFO) << "CPU freq: " << 1000.0 / double(tsc_to_ns(1000));
  return CommandSuccess();
}

void Replayer::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  if (cnt == 0) {
    RunNextModule(ctx, batch);
    return;
  }

  UpdateDynamicPlaybackSpeed();
  if (use_batching_) { // batching
    WaitToSendPkt(batch->pkts()[cnt-1]);

    if (playback_rate_mpps_ > 0) {
      // Replay at a certain packet rate
      next_pkt_time_ = curr_ts_ + cnt * 1000 / playback_rate_mpps_;
    } else if (playback_rate_mbps_ > 0) {
      // Replay at a certain bit rate
      uint64_t sum_bytes = 0;
      for (int i = 0; i < cnt; i++) {
        sum_bytes += batch->pkts()[i]->total_len();
      }
      next_pkt_time_ = curr_ts_ + sum_bytes * 8000 / playback_rate_mbps_;
    }

    RunNextModule(ctx, batch);
  } else { // non batching
    for (int i = 0; i < cnt; i++) {
      bess::Packet *pkt = batch->pkts()[i];
      // A busy loop that sends a packet until the current time passes the packet's time.
      WaitToSendPkt(pkt);
      EmitPacket(ctx, pkt, 0);

      temp_pkt_cnt_ += 1;
      temp_bit_cnt_ += pkt->total_len() * 8;
      if (playback_rate_mpps_ > 0) {
        // Replay at a certain packet rate (time unit: us)
        next_pkt_time_ = curr_ts_ + 1000 / playback_rate_mpps_;
      } else if (playback_rate_mbps_ > 0) {
        // Replay at a certain bit rate (time unit: ns)
        next_pkt_time_ = curr_ts_ + pkt->total_len() * 8000 / playback_rate_mbps_;
      }
    }
  }
}

void Replayer::UpdateDynamicPlaybackSpeed() {
  curr_ts_ = tsc_to_ns(rdtsc());
  // |playback_speed_| is updated every 200 ms.
  if (curr_ts_ - last_dynamic_speed_ts_ > 200000000) {
    if (last_dynamic_speed_idx_ < dynamic_speed_conf_.size()) {
      playback_speed_ = dynamic_speed_conf_[++last_dynamic_speed_idx_];
    }
    last_dynamic_speed_ts_ = curr_ts_;
  }
}

// Return when the current time exceeds |pkt|'s departure time.
// Note: if |use_trace_time_|, then it should first read the packet's departure time
// from the packet's payload.
void Replayer::WaitToSendPkt(bess::Packet *pkt) {
  uint64_t time_diff = 0;
  if (use_trace_time_) {
    GetPacketTimestamp(pkt, offset_, &time_diff);

    if (time_diff) {
      if (time_diff > 60000000000) { // 60 sec
        time_diff = 100;
      }
      if (playback_speed_ >= kMinPlaybackSpeed) {
        time_diff /= playback_speed_;
      } else {
        time_diff /= kMinPlaybackSpeed;
      }
    }
    next_pkt_time_ = startup_ts_ + time_diff;
  }

// Emit a packet only if |curr_ts_| passes the calculated packet timestamp
checktime:
  curr_ts_ = tsc_to_ns(rdtsc());
  if (curr_ts_ >= next_pkt_time_) {
    return;
  } else {
    goto checktime;
  }
}

ADD_MODULE(Replayer, "replayer",
           "Replay a pcap packet trace that keeps the original traffic dynamics")
