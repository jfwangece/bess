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
void NFVCore::EnqueueDequeueBatchBenchmark() {
  int bytes = llring_bytes_with_slots(32768);
  llring* testq = reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));
  int ret = llring_init(testq, 32768, 1, 1);
  if (ret) {
    std::free(testq);
    return;
  }

  bess::PacketBatch* batch[100];
  for (uint64_t i = 0; i < 100; i++) {
    batch[i] = bess::ctrl::CreatePacketBatch();
    for (uint64_t j = 0; j < 32; j++) {
      bess::Packet *pkt = current_worker.packet_pool()->Alloc();
      if (!pkt) { return; }
      batch[i]->add(pkt);
    }
  }

  uint64_t start = rdtsc();
  for (uint64_t i = 0; i < 100; i++) {
    SpEnqueue(batch[i], testq);
  }
  uint64_t total_time = rdtsc() - start;
  LOG(INFO) << "Test queue size = " << llring_count(testq);
  LOG(INFO) << "Enqueue cost = " << total_time / 100;

  start = rdtsc();
  for (uint64_t i = 0; i < 100; i++) {
    int cnt = llring_sc_dequeue_burst(testq, (void **)batch[i]->pkts(), 32);
    if (cnt == 0) {
      break;
    }
  }
  total_time = rdtsc() - start;
  LOG(INFO) << "Test queue size = " << llring_count(testq);
  LOG(INFO) << "Dequeue cost = " << total_time / 100;

  // Clean up
  for (uint64_t i = 0; i < 100; i++) {
    bess::ctrl::FreePacketBatch(batch[i]);
  }
}

void NFVCore::ShortEpochProcessBenchmark() {
  int bytes = llring_bytes_with_slots(4096);
  llring* testq = reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));
  int ret = llring_init(testq, 4096, 1, 1);
  if (ret) {
    std::free(testq);
    return;
  }

  bess::PacketBatch* batch = bess::ctrl::CreatePacketBatch();
  for (uint64_t i = 0; i < 4; i++) {
    batch->clear();
    for (uint64_t j = 0; j < 32; j++) {
      bess::Packet *pkt = current_worker.packet_pool()->Alloc();
      if (!pkt) { return; }
      batch->add(pkt);
    }
    SpEnqueue(batch, testq);
  }

  LOG(INFO) << "testq size = " << llring_count(testq);

  uint64_t start = rdtsc();

  int total_swq = 3;
  uint32_t total_cnt = llring_count(testq);
  uint32_t curr_cnt = 0;
  // scan all packets only once
  while (curr_cnt < total_cnt) {
    batch->clear();
    int cnt = llring_sc_dequeue_burst(testq, (void **)batch->pkts(), 32);
    batch->set_cnt(cnt);

    for (int i = 0; i < cnt; i++) {
      bess::Packet *pkt = batch->pkts()[i];
      if (pkt->head_len() > 10000) {
        continue;
      }
      if (pkt->data_len() > 10000) {
        continue;
      }
      int q_idx = i % total_swq;
      bess::ctrl::sw_q_state[q_idx]->sw_batch->add(pkt);
    }
    for (int i = 0; i < total_swq; i++) {
      MpEnqueue(bess::ctrl::sw_q_state[i]->sw_batch, bess::ctrl::sw_q[i]);
    }
    curr_cnt += cnt;
  }

  uint64_t total_time = rdtsc() - start;
  LOG(INFO) << "Short epoch process cost = " << total_time;
}

FlowState* NFVCore::GetFlowState(bess::Packet* pkt) {
  return *(_ptr_attr_with_offset<FlowState*>(this->attr_offset(flow_stats_attr_id_), pkt));
}

CommandResponse NFVCore::Init(const bess::pb::NFVCoreArg &arg) {
  const char *port_name;
  task_id_t tid;
  burst_ = bess::PacketBatch::kMaxBurst;

  // Configure the target CPU core ID
  core_id_ = 0;
  if (arg.core_id() > 0) {
    core_id_ = arg.core_id();
  }

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
  }

  // Configure the short-term optimization epoch size (default: 1000 us)
  short_epoch_period_ns_ = 1000000;
  max_idle_epoch_count_ = 100;
  if (arg.short_epoch_period_ns() > 0) {
    short_epoch_period_ns_ = (uint64_t)arg.short_epoch_period_ns();
    max_idle_epoch_count_ = 3000000 / arg.short_epoch_period_ns();
  }
  max_idle_epoch_count_ = 10;
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

  // Configure software queues
  local_q_ = bess::ctrl::local_q[core_id_];
  local_boost_q_ = bess::ctrl::local_boost_q[core_id_];

  local_batch_ = bess::ctrl::CreatePacketBatch();
  local_rboost_batch_ = bess::ctrl::CreatePacketBatch();
  system_dump_batch_ = bess::ctrl::CreatePacketBatch();
  split_enqueue_batch_ = bess::ctrl::CreatePacketBatch();
  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    local_sw_batch_[i] = bess::ctrl::CreatePacketBatch();
  }

  rcore_booster_q_state_ = bess::ctrl::rcore_booster_q_state;
  system_dump_q_state_ = bess::ctrl::system_dump_q_state;

  // Init epoch thresholds and packet counters
  if (bess::ctrl::short_flow_count_pkt_threshold.size() > 0) {
    // op 1: exp with different thresh settings
    epoch_packet_thresh_ = bess::ctrl::short_flow_count_pkt_threshold.begin()->second;

    large_queue_packet_thresh_ = (--bess::ctrl::short_flow_count_pkt_threshold.end())->second * bess::ctrl::rcore / bess::ctrl::ncore;
    if (arg.large_queue_scale() > 0) {
      large_queue_packet_thresh_ = (--bess::ctrl::short_flow_count_pkt_threshold.end())->second * arg.large_queue_scale();
    }

    busy_pull_round_thresh_ = (--bess::ctrl::short_flow_count_pkt_threshold.end())->second / 32;
    if (busy_pull_round_thresh_ < 1) {
      busy_pull_round_thresh_ = 1;
    }
    LOG(INFO) << "epoch thresh: pkt=" << epoch_packet_thresh_ << ", q=" << large_queue_packet_thresh_ << ", pull round=" << busy_pull_round_thresh_;
  }

  curr_rcore_ = 0;
  // curr_rcores_.clear();

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

  // Benchmark
  // EnqueueDequeueBatchBenchmark();
  // ShortEpochProcessBenchmark();

  return CommandSuccess();
}

void NFVCore::DeInit() {
  // Mark to stop the pipeline and wait until the pipeline stops
  rte_atomic16_set(&disabled_, 1);
  while (rte_atomic16_read(&disabled_) != 2) { usleep(100000); }

  // Clean the local batch / queue
  bess::ctrl::FreePacketBatch(local_batch_);
  bess::ctrl::FreePacketBatch(local_rboost_batch_);
  bess::ctrl::FreePacketBatch(system_dump_batch_);
  bess::ctrl::FreePacketBatch(split_enqueue_batch_);
  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    bess::ctrl::FreePacketBatch(local_sw_batch_[i]);
  }

  local_batch_ = nullptr;
  local_rboost_batch_ = nullptr;
  local_q_ = nullptr;
  local_boost_q_ = nullptr;

  active_sw_q_.clear();
  terminating_sw_q_.clear();
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

  // Turn on boost mode only for Ironside's runtime
  if (bess::ctrl::exp_id == 0) {
    // Boost if 1) the core has pulled many packets (i.e. 128) in this round; 2) |local_q_| is large.
    uint32_t queued_pkts = llring_count(local_q_);

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
    cnt = llring_sc_dequeue_burst(local_q_, (void **)batch->pkts(), 32);
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
      cnt = llring_sc_dequeue_burst(local_q_, (void **)batch->pkts(), 32);
      if (cnt > 0) {
        batch->set_cnt(cnt);
        SpEnqueue(batch, local_boost_q_);
      } else {
        break;
      }
    }
  }

  if (epoch_advanced) {
    // Get latency summaries to be used by the performance profiler.
    if (bess::ctrl::exp_id == 2 &&
        bess::ctrl::nfv_monitors[core_id_] != nullptr) {
      bess::ctrl::nfv_monitors[core_id_]->update_traffic_stats(curr_epoch_id_);
    }
    if (bess::ctrl::exp_id == 7) {
      uint32_t queued_pkts = llring_count(local_q_);
      if (queued_pkts >= 512) {
        bess::ctrl::nfv_ctrl->NotifyCtrlLoadBalanceNow(core_id_);
      }
    }

    bool is_active = false;
    if (epoch_packet_arrival_ > 32) {
      is_active = true;
    }
    uint32_t curr_rcore = curr_rcore_;

    ShortEpochProcess();
    SplitQToSwQ(local_q_);

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
