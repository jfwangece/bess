#include "loss_counter.h"

// Declare all static members
PerPortCounter LossCounter::per_port_counters_[64];
std::set<int> LossCounter::all_ports_;
bool LossCounter::activated_ = false;
uint64_t LossCounter::target_packet_count_ = 0;
mcslock LossCounter::lock_;


const Commands LossCounter::cmds = {
    {"get_summary", "LossCounterCommandGetSummaryArg",
     MODULE_CMD_FUNC(&LossCounter::CommandGetSummary), Command::THREAD_SAFE},
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&LossCounter::CommandClear),
     Command::THREAD_SAFE},
    {"start", "LossCounterStartArg", MODULE_CMD_FUNC(&LossCounter::CommandStart),
     Command::THREAD_SAFE},
};

CommandResponse LossCounter::Init(const bess::pb::LossCounterArg &arg) {
  if (arg.port_index() > 0) {
    port_index_ = arg.port_index();
  } else {
    LOG(WARNING) << "LossCounter must work for a specific port";
  }

  all_ports_.emplace(port_index_);

  if (arg.port_type() == 1) {
    port_type_ = kIngress;
  }

  activated_ = false;
  return CommandSuccess();
}

void LossCounter::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  now_ = rdtsc();
  int cnt = batch->cnt();

  if (port_type_ == kIngress) {
    // Count incoming packets whenever possible.
    per_port_counters_[port_index_].ingress_cnt += cnt;
  } else if (port_type_ == kEgress) {
    // Count outgoing packets only if we are now under target packet count.
    if (activated_) {
      per_port_counters_[port_index_].egress_cnt += cnt;
      if (target_packet_count_ > 0 && CountTotalPackets() > target_packet_count_) {
        activated_ = false;
      }
    } else {
      bess::Packet::Free(batch->pkts(), cnt);
      return;
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
  mcslock_node_t mynode;
  mcs_lock(&lock_, &mynode);

  activated_ = false;
  // Clear all counters.
  for (int i = 0; i < 64; ++i) {
    per_port_counters_[i].Clear();
  }

  mcs_unlock(&lock_, &mynode);
}

void LossCounter::Start() {
  mcslock_node_t mynode;
  mcs_lock(&lock_, &mynode);

  activated_ = true;

  mcs_unlock(&lock_, &mynode);
}

CommandResponse LossCounter::CommandGetSummary(
    const bess::pb::LossCounterCommandGetSummaryArg &arg) {
  bess::pb::LossCounterCommandGetSummaryResponse r;

  uint64_t total_packets = CountTotalPackets();
  uint64_t total_losses = CountTotalLosses();
  double avg_loss_rate = double(total_losses) / total_packets;
  r.set_timestamp(get_epoch_time());
  r.set_total_packets(total_packets);
  r.set_total_losses(total_losses);
  r.set_avg_loss_rate(avg_loss_rate);

  for (const auto& port : all_ports_) {
    r.add_per_port_losses(per_port_counters_[port].CountPerPortLosses());
  }

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
  target_packet_count_ = 0;
  if (arg.target_packet_count() > 0) {
    target_packet_count_ = (uint64_t)arg.target_packet_count();
  }

  Clear();
  Start();
  return CommandSuccess();
}

ADD_MODULE(LossCounter, "LossCounter",
            "measures packet loss (rate) for many pairs of ingress/egress ports")
