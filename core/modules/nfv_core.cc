#include "nfv_ctrl.h"
#include "nfv_core.h"
#include "nfv_rcore.h"
#include "nfv_monitor.h"

#include <bitset>
#include <fstream>

#include "../drivers/pmd.h"
#include "../utils/format.h"

const Commands NFVCore::cmds = {
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&NFVCore::CommandClear),
     Command::THREAD_UNSAFE},
    {"set_burst", "NFVCoreCommandSetBurstArg", MODULE_CMD_FUNC(&NFVCore::CommandSetBurst),
     Command::THREAD_SAFE},
    {"get_core_time", "EmptyArg", MODULE_CMD_FUNC(&NFVCore::CommandGetCoreTime),
     Command::THREAD_SAFE},
};

// NFVCore member functions
CommandResponse NFVCore::Init(const bess::pb::NFVCoreArg &arg) {
  const char *port_name;
  task_id_t tid;
  burst_ = bess::PacketBatch::kMaxBurst;

  // Configure the target CPU core ID
  core_id_ = 0;
  if (arg.core_id() > 0) {
    core_id_ = arg.core_id();
  }
  core_.core_id = core_id_;

  // Configure the target NIC queue
  if (!arg.port().empty()) {
    port_name = arg.port().c_str();
    qid_ = arg.qid();
    const auto& it = PortBuilder::all_ports().find(port_name);
    if (it == PortBuilder::all_ports().end()) {
      return CommandFailure(ENODEV, "Port %s not found", port_name);
    }
    port_ = it->second;
    port_id_ = ((PMDPort*)port_)->get_dpdk_port_id();

    tid = RegisterTask((void *)(uintptr_t)qid_);
    if (tid == INVALID_TASK_ID) {
      return CommandFailure(ENOMEM, "Task creation failed");
    }

    size_ = DEFAULT_SWQ_SIZE;
    // Resize(size_);
    local_queue_ = bess::ctrl::local_q[core_id_];
    local_boost_queue_ = bess::ctrl::local_boost_q[core_id_];
    local_batch_ = reinterpret_cast<bess::PacketBatch *>
          (std::aligned_alloc(alignof(bess::PacketBatch), sizeof(bess::PacketBatch)));
  }

  // Configure the short-term optimization epoch size (default: 1000 us)
  short_epoch_period_ns_ = 1000000;
  max_idle_epoch_count_ = 100;
  if (arg.short_epoch_period_ns() > 0) {
    short_epoch_period_ns_ = (uint64_t)arg.short_epoch_period_ns();
    max_idle_epoch_count_ = 5000000 / arg.short_epoch_period_ns();
  }
  LOG(INFO) << "Core " << core_id_ << ": short-term epoch = " << short_epoch_period_ns_ << " ns, max idle epochs = " << max_idle_epoch_count_;

  curr_ts_ns_ = tsc_to_ns(rdtsc());
  last_short_epoch_end_ns_ = curr_ts_ns_;
  curr_epoch_id_ = 0;

  // Add a metadata filed for recording flow stats pointer
  std::string attr_name = "flow_stats";
  using AccessMode = bess::metadata::Attribute::AccessMode;
  flow_stats_attr_id_ = AddMetadataAttr(attr_name, sizeof(FlowState*), AccessMode::kWrite);
  LOG(INFO) << core_id_ << ": flow state metadata id = " << flow_stats_attr_id_;

  // Init
  bess::ctrl::nfv_cores[core_id_] = this;

  // Begin with 0 software queue
  auto assigned = bess::ctrl::NFVCtrlRequestNSwQ(core_id_, 10);
  for (int i : assigned) {
    sw_q_.emplace_back (i);
    sw_q_.back().sw_batch = reinterpret_cast<bess::PacketBatch *>
        (std::aligned_alloc(alignof(bess::PacketBatch), sizeof(bess::PacketBatch)));
  }
  LOG(INFO) << "Core " << core_id_ << " has " << sw_q_.size() << " sw_q.";

  // Init epoch thresholds and packet counters
  if (bess::ctrl::short_flow_count_pkt_threshold.size() > 0) {
    epoch_packet_thresh_ = bess::ctrl::short_flow_count_pkt_threshold.begin()->second;

    large_queue_packet_thresh_ = (--bess::ctrl::short_flow_count_pkt_threshold.end())->second * bess::ctrl::rcore / bess::ctrl::ncore;
    if (arg.large_queue_scale() > 0) {
      large_queue_packet_thresh_ = (--bess::ctrl::short_flow_count_pkt_threshold.end())->second * arg.large_queue_scale();
    }

    busy_pull_round_thresh_ = (--bess::ctrl::short_flow_count_pkt_threshold.end())->second / 32;
    // busy_pull_round_thresh_ = (bess::ctrl::short_flow_count_pkt_threshold.begin())->second / 32;
    if (busy_pull_round_thresh_ < 1) {
      busy_pull_round_thresh_ = 1;
    }
    LOG(INFO) << "epoch thresh: pkt=" << epoch_packet_thresh_ << ", q=" << large_queue_packet_thresh_ << ", pull round=" << busy_pull_round_thresh_;
  }

  curr_rcore_ = 0;
  last_boost_ts_ns_ = 0;
  rte_atomic64_set(&sum_core_time_ns_, 0);

  epoch_packet_arrival_ = 0;
  epoch_packet_processed_ = 0;
  epoch_packet_queued_ = 0;
  num_epoch_with_large_queue_ = 0;
  epoch_flow_cache_.clear();
  unoffload_flows_.clear();
  per_flow_states_.Clear(); // CuckooMap

  update_bucket_stats_ = false;
  for (int i = 0; i < RETA_SIZE; i++) {
    local_bucket_stats_.per_bucket_packet_counter[i] = 0;
    local_bucket_stats_.per_bucket_flow_cache[i].clear();
  }

  // Run!
  rte_atomic16_set(&disabled_, 0);
  return CommandSuccess();
}

void NFVCore::DeInit() {
  // Mark to stop the pipeline and wait until the pipeline stops
  rte_atomic16_set(&disabled_, 1);
  while (rte_atomic16_read(&disabled_) != 2) { usleep(100000); }

  // Clean the local batch / queue
  if (local_batch_) {
    bess::Packet::Free(local_batch_);
    std::free(local_batch_);
    local_batch_ = nullptr;
  }
  local_queue_ = nullptr;
  local_boost_queue_ = nullptr;

  // Clean borrowed software queues
  bess::ctrl::NFVCtrlReleaseNSwQ(core_id_, sw_q_mask_);
  LOG(INFO) << "Core " << core_id_ << " releases " << sw_q_.size() << " sw_q. q_mask: " << std::bitset<64> (sw_q_mask_);

  for (auto& it : sw_q_) {
    it.sw_q = nullptr;
    if (it.sw_batch) {
      bess::Packet::Free(it.sw_batch);
      std::free(it.sw_batch);
      it.sw_batch = nullptr;
    }
  }
  sw_q_.clear();
}

CommandResponse NFVCore::CommandGetCoreTime(const bess::pb::EmptyArg &) {
  uint64_t sum = 0;
  for (int i = 0; i < bess::ctrl::ncore; i++) {
    if (bess::ctrl::nfv_cores[i] != nullptr) {
      sum += bess::ctrl::nfv_cores[i]->GetSumCoreTime();
    }
  }

  bess::pb::NFVCoreCommandGetCoreTimeResponse r;
  r.set_core_time(sum);
  return CommandSuccess(r);
}

CommandResponse NFVCore::CommandClear(const bess::pb::EmptyArg &) {
  for (auto it = per_flow_states_.begin(); it != per_flow_states_.end(); ++it) {
    if (it->second != nullptr) {
      free(it->second);
      it->second = nullptr;
    }
  }

  per_flow_states_.Clear();
  return CommandSuccess();
}

CommandResponse NFVCore::CommandSetBurst(
    const bess::pb::NFVCoreCommandSetBurstArg &arg) {
  if (arg.burst() > bess::PacketBatch::kMaxBurst) {
    return CommandFailure(EINVAL, "burst size must be [0,%zu]",
                          bess::PacketBatch::kMaxBurst);
  } else {
    burst_ = arg.burst();
    return CommandSuccess();
  }
}

// std::string NFVCore::GetDesc() const {
//   return bess::utils::Format("%s:%hhu/%d", port_->name().c_str(), qid_, llring_count(local_queue_));
// }

/* Get a batch from NIC and send it to downstream */
struct task_result NFVCore::RunTask(Context *ctx, bess::PacketBatch *batch,
                                     void *arg) {
  Port *p = port_;
  const queue_t qid = (queue_t)(uintptr_t)arg;
  bool epoch_advanced = false;

  // Read the CPU cycle counter for better accuracy
  curr_ts_ns_ = tsc_to_ns(rdtsc());
  if (curr_ts_ns_ - last_short_epoch_end_ns_ > short_epoch_period_ns_) {
    epoch_advanced = true;
  }

  // For graceful termination
  if (epoch_advanced) {
    if (rte_atomic16_read(&disabled_) == 1) {
      rte_atomic16_set(&disabled_, 2);
      return {.block = false, .packets = 0, .bits = 0};
    }
  }

  // status: -95 (not supported)
  // int status = rte_eth_rx_descriptor_status(port_id_, qid, large_queue_packet_thresh_);

  // Busy pulling from the NIC queue
  int total_pkts = 0;
  int cnt = 0;
  uint32_t pull_rounds = 0;
  while (pull_rounds++ < 8) {
    batch->clear();
    cnt = p->RecvPackets(qid, batch->pkts(), 32);
    batch->set_cnt(cnt);
    if (cnt > 0) {
      total_pkts += cnt;
      // To append |per_flow_states_|
      // Update the number of packets / flows that have arrived:
      // Update |epoch_packet_arrival_| and |epoch_flow_cache_|
      UpdateStatsOnFetchBatch(batch);
    }
    if (cnt < 32) {
      break;
    }
  }

  // Boost if 1) the core has pulled many packets (i.e. 128) in this round; 2) |local_queue_| is large.
  uint32_t queued_pkts = llring_count(local_queue_);
  if (last_boost_ts_ns_ == 0) {
    if (update_bucket_stats_ ||
        epoch_advanced ||
        pull_rounds >= busy_pull_round_thresh_ ||
        queued_pkts >= large_queue_packet_thresh_) {
      last_boost_ts_ns_ = tsc_to_ns(rdtsc()); // boost!
    }
  } else {
    if (queued_pkts * 2 < large_queue_packet_thresh_) {
      uint64_t core_diff = tsc_to_ns(rdtsc()) - last_boost_ts_ns_;
      rte_atomic64_add(&sum_core_time_ns_, core_diff);
      last_boost_ts_ns_ = 0;
    }
  }

  if (update_bucket_stats_) {
    for (int i = 0; i < SHARD_NUM; i++) {
      bess::ctrl::pcpb_packet_count[core_id_][i] = local_bucket_stats_.per_bucket_packet_counter[i];
      bess::ctrl::pcpb_flow_count[core_id_][i] = local_bucket_stats_.per_bucket_flow_cache[i].size();
      local_bucket_stats_.per_bucket_packet_counter[i] = 0;
      local_bucket_stats_.per_bucket_flow_cache[i].clear();
    }
    bess::ctrl::nfv_ctrl->NotifyLongTermStatsReady();
    update_bucket_stats_ = false;
  }

  if (last_boost_ts_ns_ == 0) {
    // Process one batch
    batch->clear();
    cnt = llring_sc_dequeue_burst(local_queue_, (void **)batch->pkts(), 32);
    if (cnt > 0) {
      batch->set_cnt(cnt);
      // Update |epoch_packet_processed_| and |per_flow_states_|, i.e.
      // the number of packets and flows processed during the current epoch.
      UpdateStatsPreProcessBatch(batch);
      ProcessBatch(ctx, batch);
    }
  } else { // boost!
    for (int i = 0; i < 2; i++) {
      batch->clear();
      cnt = llring_sc_dequeue_burst(local_queue_, (void **)batch->pkts(), 32);
      if (cnt > 0) {
        batch->set_cnt(cnt);
        BestEffortEnqueue(batch, local_boost_queue_);
      }
    }
  }

  if (epoch_advanced) {
    // Get latency summaries to be used by the performance profiler.
    if (bess::ctrl::exp_id == 1 &&
        bess::ctrl::nfv_monitors[core_id_] != nullptr) {
      bess::ctrl::nfv_monitors[core_id_]->update_traffic_stats(curr_epoch_id_);
    }

    bool is_active = false;
    if (epoch_packet_arrival_ > 10) {
      is_active = true;
    }
    uint32_t curr_rcore = curr_rcore_;

    ShortEpochProcess();
    SplitQToSwQ(local_queue_);

    // Update CPU core usage
    uint64_t now = tsc_to_ns(rdtsc());
    if (is_active) {
      uint64_t core_diff = (1 + curr_rcore) * (now - last_short_epoch_end_ns_);
      rte_atomic64_add(&sum_core_time_ns_, core_diff);
    }
    curr_epoch_id_ += 1;
    last_short_epoch_end_ns_ = now;
  }

  return {.block = false, .packets = (uint32_t)total_pkts, .bits = 0};
}

/* Get a batch from upstream */
void NFVCore::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  RunNextModule(ctx, batch);
}

uint64_t NFVCore::GetSumCoreTime() {
  return rte_atomic64_read(&sum_core_time_ns_);
}

ADD_MODULE(NFVCore, "nfv_core", "It handles traffic burstiness at a normal core")
