#include "faas_ctl.h"

#include <algorithm>
#include "../utils/common.h"
#include "../utils/endian.h"
#include "../utils/ether.h"
#include "../utils/format.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/time.h"
#include "../utils/udp.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;
using bess::utils::Udp;

// The default number of CPU cores
const int kTotalNumCores = 40;
// The default flow-rate re-calc duration is 500 millisecond.
const double kFlowRateCalcDurationInSecond = 0.5;
// The default cluster-info re-calc duration is 500 millisecond.
const double kClusterUpdateDurationInSecond = 0.5;
// A flow is not active if no packet arrives within the last 5 second.
const double kFlowTimeoutInSecond = 5;


const Commands FaaSController::cmds = {
    {"get_summary", "FaaSControllerCommandGetSummaryArg",
     MODULE_CMD_FUNC(&FaaSController::CommandGetSummary), Command::THREAD_SAFE},
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&FaaSController::CommandClear),
     Command::THREAD_SAFE},
};

uint32_t FaaSController::UpdateFlowInfo(const uint64_t& tsc) {
  uint32_t cnt = 0;
  uint64_t duration;

  for (auto it = map_coreinfo_.begin(); it != map_coreinfo_.end(); it++) {
    it->second.total_pkt_rate = 0;
  }
  auto it = map_l3flow_to_counter_.begin();
  while (it != map_l3flow_to_counter_.end()) {
    duration = tsc - (it->second).last_pkt_tsc;
    if (duration > flow_entry_timeout_tsc_) {
      // Deletes a flow entry if the entry timeouts.
      it = map_l3flow_to_counter_.erase(it);
    } else if (duration < flow_timeout_tsc_) {
      // Count an active flow.
      cnt += 1;
      map_coreinfo_[(it->second).core_id].total_pkt_rate += (it->second).flow_rate_kpps;
      ++it;
    }
  }
  return cnt;
}

uint32_t FaaSController::UpdateCoreInfo() {
  uint32_t cnt = 0;
  double max_core_rate = 0;
  curr_target_core_ = 0;

  for (auto it = map_coreinfo_.begin(); it != map_coreinfo_.end(); it++) {
    if (it->second.total_pkt_rate == 0) {
      it->second.is_active = false;
    } else {
      it->second.is_active = true;
      cnt += 1;
    }
    if (it->second.total_pkt_rate > max_per_core_kpps_) {
      continue;
    }
    if (it->second.total_pkt_rate >= max_core_rate) {
      max_core_rate = it->second.total_pkt_rate;
      curr_target_core_ = it->first;
    }
  }
  if (cnt > 0) {
    sum_core_time_ += active_cores_ * update_cluster_period_tsc_;
    sum_running_time_ += update_cluster_period_tsc_;
    last_avg_cores_ = sum_core_time_ / sum_running_time_;
  } else {
    sum_core_time_ = 0;
    sum_running_time_ = 0;
  }
  return cnt;
}

void FaaSController::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  uint64_t now = rdtsc();

  for (int i = 0; i < cnt; ++i) {
    bess::Packet *pkt = batch->pkts()[i];
    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    new_l3flow_ = std::make_tuple(ip->src, ip->dst);

    auto it = map_l3flow_to_counter_.find(new_l3flow_);
    if (it == map_l3flow_to_counter_.end()) {
      // A new flow.
      map_l3flow_to_counter_[new_l3flow_] = PerFlowCounter(1, now);
      map_l3flow_to_counter_[new_l3flow_].core_id = curr_target_core_;
      count_new_flows_ += 1;
    } else {
      (it->second).pkt_cnt += 1;
      (it->second).last_pkt_tsc = now;
      if (now - it->second.last_calc_tsc > rate_calc_period_tsc_) {
        (it->second).flow_rate_kpps = tsc_hz / 1000 * ((it->second).pkt_cnt - (it->second).last_calc_pkt_cnt) / (now - (it->second).last_calc_tsc);
        (it->second).last_calc_pkt_cnt = (it->second).pkt_cnt;
        (it->second).last_calc_tsc = now;
      }
    }
  }

  if (now - last_update_cluster_tsc_ >= update_cluster_period_tsc_) {
    flow_arrival_rate_ = (double)count_new_flows_ * tsc_hz / (rdtsc() - last_update_cluster_tsc_);
    peak_flow_arrival_rate_ = std::max(peak_flow_arrival_rate_, flow_arrival_rate_);

    active_flows_ = UpdateFlowInfo(now);
    peak_active_flows_ = std::max(peak_active_flows_, active_flows_);
    active_cores_ = UpdateCoreInfo();

    // Reset the global flow counter.
    count_new_flows_ = 0;
    last_update_cluster_tsc_ = now;
  }

  RunNextModule(ctx, batch);
}

void FaaSController::Clear() {
  mcslock_node_t mynode;
  mcs_lock(&lock_, &mynode);
  map_l3flow_to_counter_.clear();
  count_new_flows_ = 0;
  last_update_cluster_tsc_ = rdtsc();

  active_flows_ = 0;
  peak_active_flows_ = 0;

  flow_arrival_rate_ = 0;
  peak_flow_arrival_rate_ = 0;
  mcs_unlock(&lock_, &mynode);
}

CommandResponse FaaSController::Init(const bess::pb::FaaSControllerArg &arg) {
  map_l3flow_to_counter_.clear();

  if (arg.per_core_rate_kpps() > 0) {
    max_per_core_kpps_ = arg.per_core_rate_kpps();
  }

  rate_calc_period_tsc_ = kFlowRateCalcDurationInSecond * tsc_hz;
  if (arg.measure_period() > 0) {
    update_cluster_period_tsc_ = arg.measure_period() * tsc_hz;
  } else {
    update_cluster_period_tsc_ = kClusterUpdateDurationInSecond * tsc_hz;
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

  for (int i = 0; i < kTotalNumCores; ++i) {
    map_coreinfo_[i] = CoreInfo();
  }

  count_new_flows_ = 0;
  last_update_cluster_tsc_ = rdtsc();
  return CommandSuccess();
}

CommandResponse FaaSController::CommandGetSummary(
    const bess::pb::FaaSControllerCommandGetSummaryArg &arg) {
  bess::pb::FaaSControllerCommandGetSummaryResponse r;

  r.set_timestamp(get_epoch_time());
  r.set_flow_arrival_rate(flow_arrival_rate_);
  r.set_peak_flow_arrival_rate(peak_flow_arrival_rate_);
  r.set_active_flows(active_flows_);
  r.set_peak_active_flows(peak_active_flows_);

  if (arg.clear()) {
    Clear();
  }

  return CommandSuccess(r);
}

CommandResponse FaaSController::CommandClear(const bess::pb::EmptyArg &) {
  Clear();
  return CommandResponse();
}

std::string FaaSController::GetDesc() const {
  return bess::utils::Format("%d flows, %d %.2f cores", active_flows_, active_cores_, last_avg_cores_);
}

ADD_MODULE(FaaSController, "FaaSCtl",
            "emulates faas controller to load balance flows")
