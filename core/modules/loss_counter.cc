#include "loss_counter.h"
#include "timestamp.h"

// Declare all static members
PerPortCounter LossCounter::per_port_counters_[64];
std::set<int> LossCounter::all_ports_;
bool LossCounter::is_activated_ = false;
uint64_t LossCounter::packet_count_offset_ = 0;
uint64_t LossCounter::packet_count_target_ = 0;
mcslock LossCounter::lock_;
std::mutex LossCounter::mu_;

const uint64_t kDefaultPacketCountTarget = 1000000;

const Commands LossCounter::cmds = {
    {"get_summary", "LossCounterCommandGetSummaryArg",
     MODULE_CMD_FUNC(&LossCounter::CommandGetSummary), Command::THREAD_SAFE},
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&LossCounter::CommandClear),
     Command::THREAD_SAFE},
    {"start", "LossCounterStartArg", MODULE_CMD_FUNC(&LossCounter::CommandStart),
     Command::THREAD_SAFE},
};

CommandResponse LossCounter::Init(const bess::pb::LossCounterArg &arg) {
  const std::lock_guard<std::mutex> lock(mu_);

  if (arg.offset() > 0) {
    offset_ = arg.offset();
  } else {
    offset_ = 64;
  }

  if (arg.port_index() > 0) {
    port_index_ = arg.port_index();
  } else {
    LOG(WARNING) << "LossCounter must work for a specific port";
  }

  // |all_ports| is a static class member.
  all_ports_.emplace(port_index_);

  if (arg.port_type() == 1) {
    port_type_ = kIngress;
  }

  is_activated_ = false;
  return CommandSuccess();
}

static inline bool is_marked(bess::Packet *pkt, size_t offset) {
  auto *marker = pkt->head_data<Timestamp::MarkerType *>(offset);
  if (*marker == Timestamp::kMarker) {
    return true;
  }
  return false;
}

static inline void mark_packet(bess::Packet *pkt, size_t offset) {
  Timestamp::MarkerType *marker;
  const size_t kStampSize = sizeof(*marker);
  size_t room = pkt->data_len() - offset;
  if (room < kStampSize) {
    void *ret = pkt->append(kStampSize - room);
    if (!ret) {
      // not enough tailroom for timestamp. give up
      return;
    }
  }

  marker = pkt->head_data<Timestamp::MarkerType *>(offset);
  *marker = Timestamp::kMarker;
}

void LossCounter::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  now_ = rdtsc();
  int cnt = batch->cnt();
  size_t offset = offset_;

  const std::lock_guard<std::mutex> lock(mu_);

  if (port_type_ == kIngress) {
    for (int i = 0; i < cnt; i++) {
      if (is_marked(batch->pkts()[i], offset)) {
        per_port_counters_[port_index_].ingress_cnt += 1;
      }
    }
  } else if (port_type_ == kEgress) {
    // Start counting when we hits the packet count offset.
    if (!per_port_counters_[port_index_].is_counting_) {
      if (per_port_counters_[port_index_].egress_cnt + cnt > packet_count_offset_) {
        per_port_counters_[port_index_].Start();
      } else {
        per_port_counters_[port_index_].egress_cnt += cnt;
      }
    }

    if (per_port_counters_[port_index_].is_counting_) {
      if (is_activated_) {
        // Mark and count.
        for (int i = 0; i < cnt; i++) {
          mark_packet(batch->pkts()[i], offset);
        }
        per_port_counters_[port_index_].egress_cnt += cnt;

        if (packet_count_target_ > 0 && CountTotalPackets() > packet_count_target_) {
          is_activated_ = false;
        }
      } else {
        bess::Packet::Free(batch->pkts(), cnt);
        return;
      }
    }
  }

  RunNextModule(ctx, batch);
}

uint64_t LossCounter::CountTotalLosses() {
  uint64_t count = 0;
  for (const auto& port : all_ports_) {
    count += per_port_counters_[port].CountPerPortLosses();
  }
  return count;
}

uint64_t LossCounter::CountTotalPackets() {
  uint64_t count = 0;
  for (const auto& port : all_ports_) {
    count += per_port_counters_[port].egress_cnt;
  }
  return count;
}

void LossCounter::Clear() {
  const std::lock_guard<std::mutex> lock(mu_);

  // Clear all counters.
  for (int i = 0; i < 64; ++i) {
    per_port_counters_[i].Clear();
  }
}

void LossCounter::Start() {
  const std::lock_guard<std::mutex> lock(mu_);

  // Clear all counters.
  for (int i = 0; i < 64; ++i) {
    per_port_counters_[i].Clear();
  }
  is_activated_ = true;
}

CommandResponse LossCounter::CommandGetSummary(
    const bess::pb::LossCounterCommandGetSummaryArg &arg) {
  bess::pb::LossCounterCommandGetSummaryResponse r;

  mu_.lock();
  uint64_t total_packets = CountTotalPackets();
  uint64_t total_losses = CountTotalLosses();
  mu_.unlock();

  double avg_loss_rate = 0.0;
  if (total_packets > 0) {
    avg_loss_rate = double(total_losses) / total_packets;
  }

  r.set_timestamp(get_epoch_time());
  r.set_total_packets(total_packets);
  r.set_total_losses(total_losses);
  r.set_avg_loss_rate(avg_loss_rate);

  mu_.lock();
  for (const auto& port : all_ports_) {
    bess::pb::LossCounterCommandGetSummaryResponse_PerPortLossCounterSummary* \
      p = r.add_per_port_summary();
    p->set_port_idx(port);
    p->set_packets(per_port_counters_[port].egress_cnt);
    p->set_losses(per_port_counters_[port].CountPerPortLosses());
  }
  mu_.unlock();

  if (arg.clear()) {
    Clear();
  }

  return CommandSuccess(r);
}

CommandResponse LossCounter::CommandClear(const bess::pb::EmptyArg &) {
  Clear();
  return CommandResponse();
}

CommandResponse LossCounter::CommandStart(const bess::pb::LossCounterStartArg &arg) {
  if (arg.packet_count_offset() > 0) {
    packet_count_offset_ = (uint64_t)arg.packet_count_offset();
  } else {
    packet_count_offset_ = 0;
  }
  if (arg.packet_count_target() > 0) {
    packet_count_target_ = (uint64_t)arg.packet_count_target();
  } else {
    packet_count_target_ = kDefaultPacketCountTarget;
  }

  Clear();
  Start();
  return CommandSuccess();
}

ADD_MODULE(LossCounter, "LossCounter",
            "measures packet loss (rate) for many pairs of ingress/egress ports")
