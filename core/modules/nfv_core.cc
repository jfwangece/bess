#include "nfv_core.h"

#include <bitset>
#include <fstream>

#include "../drivers/pmd.h"
#include "../utils/format.h"

const Commands NFVCore::cmds = {
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&NFVCore::CommandClear),
     Command::THREAD_UNSAFE},
    {"set_burst", "NFVCoreCommandSetBurstArg", MODULE_CMD_FUNC(&NFVCore::CommandSetBurst),
     Command::THREAD_SAFE},
};

// NFVCore member functions
int NFVCore::Resize(int slots) {
  struct llring *old_queue = local_queue_;
  struct llring *new_queue;

  int bytes = llring_bytes_with_slots(slots);

  new_queue =
      reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));
  if (!new_queue) {
    return -ENOMEM;
  }

  int ret = llring_init(new_queue, slots, 1, 1);
  if (ret) {
    std::free(new_queue);
    return -EINVAL;
  }

  /* migrate packets from the old queue */
  if (old_queue) {
    bess::Packet *pkt;

    while (llring_sc_dequeue(old_queue, (void **)&pkt) == 0) {
      ret = llring_sp_enqueue(new_queue, pkt);
      if (ret == -LLRING_ERR_NOBUF) {
        bess::Packet::Free(pkt);
      }
    }

    std::free(old_queue);
  }

  local_queue_ = new_queue;
  size_ = slots;
  return 0;
}

CommandResponse NFVCore::Init(const bess::pb::NFVCoreArg &arg) {
  const char *port_name;
  task_id_t tid;
  burst_ = bess::PacketBatch::kMaxBurst;

  // Configure the target NIC queue
  if (!arg.port().empty()) {
    port_name = arg.port().c_str();
    qid_ = arg.qid();
    const auto& it = PortBuilder::all_ports().find(port_name);
    if (it == PortBuilder::all_ports().end()) {
      return CommandFailure(ENODEV, "Port %s not found", port_name);
    }
    port_ = it->second;

    tid = RegisterTask((void *)(uintptr_t)qid_);
    if (tid == INVALID_TASK_ID) {
      return CommandFailure(ENOMEM, "Task creation failed");
    }

    Resize(2048);
    local_batch_ = reinterpret_cast<bess::PacketBatch *>
          (std::aligned_alloc(alignof(bess::PacketBatch), sizeof(bess::PacketBatch)));
  }

  // Configure the target CPU core ID
  core_id_ = 0;
  if (arg.core_id() > 0) {
    core_id_ = arg.core_id();
  }
  core_.core_id = core_id_;

  // Add a metadata filed for recording flow stats pointer
  std::string attr_name = "flow_stats";
  using AccessMode = bess::metadata::Attribute::AccessMode;
  flow_stats_attr_id_ = AddMetadataAttr(attr_name, sizeof(uint64_t), AccessMode::kWrite);

  // Init
  bess::ctrl::nfv_cores[core_id_] = this;

  // Begin with 0 software queue
  sw_q_mask_ = bess::ctrl::NFVCtrlRequestNSwQ(core_id_, 4);
  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    uint64_t sw_q_idx = (1ULL << i) & sw_q_mask_;
    if (sw_q_idx != 0) {
      sw_q_.emplace_back (i);
      sw_q_.back().sw_batch = reinterpret_cast<bess::PacketBatch *>
          (std::aligned_alloc(alignof(bess::PacketBatch), sizeof(bess::PacketBatch)));
    }
  }
  LOG(INFO) << "Core " << core_id_ << " has " << sw_q_.size() << " sw_q. q_mask: " << std::bitset<64> (sw_q_mask_);

  epoch_flow_thresh_ = 20;
  epoch_packet_thresh_ = 40;
  epoch_packet_arrival_ = 0;
  epoch_packet_processed_ = 0;
  epoch_packet_queued_ = 0;
  epoch_flow_cache_.clear();
  per_flow_states_.clear();

  // Run!
  rte_atomic16_set(&mark_to_disable_, 0);
  rte_atomic16_set(&disabled_, 0);
  return CommandSuccess();
}

void NFVCore::DeInit() {
  // Mark to stop the pipeline and wait until the pipeline stops
  rte_atomic16_set(&mark_to_disable_, 1);
  while (rte_atomic16_read(&disabled_) == 0) { usleep(100000); }

  bess::Packet *pkt;
  // Clean the local batch / queue
  if (local_batch_) {
    bess::Packet::Free(local_batch_);
    std::free(local_batch_);
    local_batch_ = nullptr;
  }
  if (local_queue_) {
    while (llring_sc_dequeue(local_queue_, (void **)&pkt) == 0) {
      bess::Packet::Free(pkt);
    }
    std::free(local_queue_);
    local_queue_ = nullptr;
  }

  // Clean (borrowed) software queues
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

CommandResponse NFVCore::CommandClear(const bess::pb::EmptyArg &) {
  for (auto& it : per_flow_states_) {
    if (it.second != nullptr) {
      free(it.second);
      it.second = nullptr;
    }
  }

  per_flow_states_.clear();
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

std::string NFVCore::GetDesc() const {
  return bess::utils::Format("%s:%hhu/%d", port_->name().c_str(), qid_, llring_count(local_queue_));
}

/* Get a batch from NIC and send it to downstream */
struct task_result NFVCore::RunTask(Context *ctx, bess::PacketBatch *batch,
                                     void *arg) {
  if (rte_atomic16_read(&mark_to_disable_) == 1) {
    rte_atomic16_set(&disabled_, 1);
    return {.block = false, .packets = 0, .bits = 0};
  }
  if (rte_atomic16_read(&disabled_) == 1) {
    return {.block = false, .packets = 0, .bits = 0};
  }

  Port *p = port_;
  const queue_t qid = (queue_t)(uintptr_t)arg;
  const int burst = ACCESS_ONCE(burst_);

  // Read the CPU cycle counter for better accuracy
  curr_ts_ns_ = tsc_to_ns(rdtsc());

  MaybeEpochEndProcessBatch(batch);

  // Busy pulling from the NIC queue
  uint32_t cnt = 0, pull_rounds = 0;
  while (pull_rounds++ < 10) {
    cnt = p->RecvPackets(qid, batch->pkts(), 32);
    batch->set_cnt(cnt);
    if (cnt) {
      // To append |per_flow_states_|
      // Update the number of packets / flows that have arrived:
      // Update |epoch_packet_arrival_| and |epoch_flow_cache_|
      UpdateStatsOnFetchBatch(batch);
    }
    if (cnt < 32) {
      break;
    }
  }

  // Process one batch
  cnt = llring_sc_dequeue_burst(local_queue_, (void **)batch->pkts(), burst);
  if (cnt == 0) {
    return {.block = false, .packets = 0, .bits = 0};
  }
  batch->set_cnt(cnt);

  uint64_t total_bytes = 0;
  for (uint32_t i = 0; i < cnt; i++) {
    total_bytes += batch->pkts()[i]->total_len();
  }

  // Update the number of packets / flows processed:
  // |epoch_packet_processed_| and |per_flow_states_|
  UpdateStatsPreProcessBatch(batch);

  ProcessBatch(ctx, batch);

  return {.block = false,
          .packets = cnt,
          .bits = (total_bytes + cnt * 24) * 8};
}

/* Get a batch from upstream */
void NFVCore::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  RunNextModule(ctx, batch);
}

ADD_MODULE(NFVCore, "nfv_core", "It handles traffic burstiness at a normal core")
