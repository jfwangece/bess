#include "flow_stats.h"

#include <algorithm>
#include "../utils/common.h"
#include "../utils/endian.h"
#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/time.h"
#include "../utils/udp.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;
using bess::utils::Udp;

// The default measurement duration is 500 millisecond.
const double kMeasurementDurationInSecond = 0.5;
// A flow is not active if no packet arrives within the last 5 second.
const double kFlowTimeoutInSecond = 5;

const Commands FlowStats::cmds = {
    {"get_summary", "FlowStatsCommandGetSummaryArg",
     MODULE_CMD_FUNC(&FlowStats::CommandGetSummary), Command::THREAD_SAFE},
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&FlowStats::CommandClear),
     Command::THREAD_SAFE},
};

uint32_t FlowStats::CountActiveFlows(const uint64_t& tsc) {
  uint32_t cnt = 0;
  uint64_t duration;
  auto it = map_flow_to_counter_.begin();
  while (it != map_flow_to_counter_.end()) {
    duration = tsc - (it->second).last_pkt_tsc;
    if (duration > flow_entry_timeout_tsc_) {
      // Deletes a flow entry if the entry timeouts.
      it = map_flow_to_counter_.erase(it);
    } else if (duration < flow_timeout_tsc_) {
      // Count an active flow.
      cnt += 1;
      ++it;
    }
  }

  return cnt;
}

void FlowStats::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  uint64_t now = rdtsc();

  for (int i = 0; i < cnt; ++i) {
    bess::Packet *pkt = batch->pkts()[i];
    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);

    // ip->header_length (1 word = 4 bytes)
    size_t ip_hdr_len = (ip->header_length) << 2;
    if (ip->protocol == Ipv4::Proto::kTcp) {
      Tcp *tcp = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_hdr_len);
      new_flow_ = std::make_tuple(ip->src, ip->dst, ip->protocol, tcp->src_port, tcp->dst_port);
    } else if (ip->protocol == Ipv4::Proto::kUdp) {
      Udp *udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) + ip_hdr_len);
      new_flow_ = std::make_tuple(ip->src, ip->dst, ip->protocol, udp->src_port, udp->dst_port);
    } else {
      continue;
    }

    auto it = map_flow_to_counter_.find(new_flow_);
    if (it == map_flow_to_counter_.end()) {
      // A new flow.
      map_flow_to_counter_[new_flow_] = PerFlowCounter();
      count_new_flows_ += 1;
    }
    (it->second).pkt_cnt += 1;
    (it->second).temp_pkt_cnt += 1;
    (it->second).last_pkt_tsc = now;
  }

  if (now - last_measure_tsc_ >= measure_period_tsc_) {
    uint64_t peak_per_flow_temp_pkt_cnt = 0;
    for (auto &f : map_flow_to_counter_) {
      if (f.second.temp_pkt_cnt > peak_per_flow_temp_pkt_cnt) {
        peak_per_flow_temp_pkt_cnt = f.second.temp_pkt_cnt;
      }
      f.second.temp_pkt_cnt = 0;
    }
    peak_per_flow_pkt_rate_ = std::max(peak_per_flow_pkt_rate_,
        (double)peak_per_flow_temp_pkt_cnt);
        // (double)peak_per_flow_temp_pkt_cnt * tsc_hz / (now - last_measure_tsc_));

    flow_arrival_rate_ = (double)count_new_flows_ * tsc_hz / (now - last_measure_tsc_);
    peak_flow_arrival_rate_ = std::max(peak_flow_arrival_rate_, flow_arrival_rate_);

    active_flows_ = CountActiveFlows(now);
    peak_active_flows_ = std::max(peak_active_flows_, active_flows_);

    // Reset the global flow counter.
    count_new_flows_ = 0;
    last_measure_tsc_ = now;
  }

  RunNextModule(ctx, batch);
}

void FlowStats::Clear() {
  mcslock_node_t mynode;
  mcs_lock(&lock_, &mynode);
  map_flow_to_counter_.clear();
  count_new_flows_ = 0;
  last_measure_tsc_ = rdtsc();

  active_flows_ = 0;
  peak_active_flows_ = 0;

  flow_arrival_rate_ = 0;
  peak_flow_arrival_rate_ = 0;
  mcs_unlock(&lock_, &mynode);
}

CommandResponse FlowStats::Init(const bess::pb::FlowStatsArg &arg) {
  map_flow_to_counter_.clear();

  if (arg.measure_period() > 0) {
    measure_period_tsc_ = arg.measure_period() * tsc_hz;
  } else {
    measure_period_tsc_ = kMeasurementDurationInSecond * tsc_hz;
  }

  if (arg.flow_timeout() > 0) {
    flow_timeout_tsc_ = arg.flow_timeout() * tsc_hz;
  } else {
    flow_timeout_tsc_ = kFlowTimeoutInSecond * tsc_hz;
  }

  if (arg.flow_entry_timeout() > 0) {
    flow_entry_timeout_tsc_ = arg.flow_entry_timeout() * tsc_hz;
  } else {
    flow_entry_timeout_tsc_ = flow_timeout_tsc_;
  }

  count_new_flows_ = 0;
  last_measure_tsc_ = rdtsc();
  return CommandSuccess();
}

CommandResponse FlowStats::CommandGetSummary(
    const bess::pb::FlowStatsCommandGetSummaryArg &arg) {
  bess::pb::FlowStatsCommandGetSummaryResponse r;

  r.set_timestamp(get_epoch_time());
  r.set_flow_arrival_rate(flow_arrival_rate_);
  r.set_peak_flow_arrival_rate(peak_flow_arrival_rate_);
  r.set_peak_flow_pkt_rate(peak_per_flow_pkt_rate_);
  r.set_active_flows(active_flows_);
  r.set_peak_active_flows(peak_active_flows_);

  if (arg.clear()) {
    Clear();
  }

  return CommandSuccess(r);
}

CommandResponse FlowStats::CommandClear(const bess::pb::EmptyArg &) {
  Clear();
  return CommandResponse();
}

ADD_MODULE(FlowStats, "FlowStats",
            "measures flow statistics (flow arrival rate and active flows)")
