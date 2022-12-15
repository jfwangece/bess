#include "nfv_ctrl.h"
#include "nfv_ctrl_msg.h"
#include "nfv_core.h"
#include "nfv_rcore.h"
#include "nfv_monitor.h"
#include "metron_core.h"
#include "measure.h"

#include "../module_graph.h"

/// Initialize global NFV control messages
namespace bess {
namespace ctrl {

// NFVCtrl system components
NFVCtrl* nfv_ctrl = nullptr;
NFVCore* nfv_cores[DEFAULT_INVALID_CORE_ID] = {nullptr};
NFVRCore* nfv_booster[DEFAULT_INVALID_CORE_ID] = {nullptr};
NFVRCore* nfv_rcores[DEFAULT_INVALID_CORE_ID] = {nullptr};
NFVRCore* nfv_rcore_booster = nullptr;
NFVRCore* nfv_system_dumper = nullptr;

NFVMonitor* nfv_monitors[DEFAULT_INVALID_CORE_ID] = {nullptr};
MetronCore* metron_cores[DEFAULT_INVALID_CORE_ID] = {nullptr};

Measure* sys_measure = nullptr;
PMDPort* pmd_port = nullptr;

std::shared_mutex nfvctrl_worker_mu;
std::shared_mutex nfvctrl_bucket_mu;

// Default: 0, i.e. a normal run
int exp_id = 0;

// Long-term and short-term NF profiles
std::map<uint64_t, uint64_t> long_flow_count_pps_threshold;
std::map<uint32_t, uint32_t> short_flow_count_pkt_threshold;
std::map<uint16_t, uint16_t> trans_buckets;

// A software queue as this server's trash bin. Any packets that are
// moved into this queue will be freed without any processing.
struct llring* system_dump_q = nullptr;
struct llring* rcore_boost_q = nullptr;
struct llring* local_q[DEFAULT_LOCALQ_COUNT] = {nullptr};
struct llring* local_boost_q[DEFAULT_LOCALQ_COUNT] = {nullptr};
struct llring* local_mc_q[DEFAULT_NICQ_COUNT] = {nullptr};

struct llring* sw_q[DEFAULT_SWQ_COUNT] = {nullptr};

// sw_q can be assigned if |up_core_id| is invalid
SoftwareQueueState* sw_q_state[DEFAULT_SWQ_COUNT] = {nullptr};
SoftwareQueueState* rcore_booster_q_state = nullptr;
SoftwareQueueState* system_dump_q_state = nullptr;

// The number of dedicated cores and aux cores in an Ironside worker.
int ncore = 0;
int rcore = 0;

uint64_t pc_max_batch_delay[100] = {0};
uint64_t pcpb_packet_count[DEFAULT_INVALID_CORE_ID][512] = {0};
uint64_t pcpb_flow_count[DEFAULT_INVALID_CORE_ID][512] = {0};

// core is in-use if true
bool core_state[DEFAULT_INVALID_CORE_ID] = {false};
// rcore can be assigned if true
bool rcore_state[DEFAULT_INVALID_CORE_ID] = {false};
// the number of long epochs in which a core has been live
int core_liveness[DEFAULT_INVALID_CORE_ID] = {0};
// the number of in-use normal cores on a server
int worker_ncore[DEFAULT_INVALID_WORKER_ID] = {0};

// the packet rate on a server
uint32_t worker_packet_rate[DEFAULT_INVALID_WORKER_ID] = {0};

/// Global software queue / reserved core management functions
// bess/core/main.cc calls this function to init when bessd starts
void NFVCtrlMsgInit() {
  size_t sw_qsize = DEFAULT_SWQ_SIZE;
  int bytes = llring_bytes_with_slots(sw_qsize);

  int ret;
  for (int i = 0; i < DEFAULT_LOCALQ_COUNT; i++) {
    // |local_q| used by all dedicated cores
    local_q[i] = reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));
    ret = llring_init(local_q[i], sw_qsize, 1, 1);
    if (ret) {
      std::free(local_q[i]);
      LOG(FATAL) << "llring_init failed on local queue " << i;
      break;
    }

    // |local_boost_q| is used by all dedicated cores in the 'boost' mode.
    local_boost_q[i] = reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));
    ret = llring_init(local_boost_q[i], sw_qsize, 1, 1);
    if (ret) {
      std::free(local_boost_q[i]);
      LOG(FATAL) << "llring_init failed on local boost queue " << i;
      break;
    }
  }

  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    // |sw_q| used by all aux cores:
    // single-producer and single-consumer
    sw_q[i] = reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));
    ret = llring_init(sw_q[i], sw_qsize, 1, 1);
    if (ret) {
      std::free(sw_q[i]);
      LOG(FATAL) << "llring_init failed on software queue " << i;
      break;
    }

    // Note: each SoftwareQueueState object has to be initialized as
    // 'rte_malloc' does not initialize it when allocating memory
    sw_q_state[i] = reinterpret_cast<SoftwareQueueState*>(
        std::aligned_alloc(alignof(SoftwareQueueState), sizeof(SoftwareQueueState)));

    sw_q_state[i]->SetUpCoreID(DEFAULT_INVALID_CORE_ID);
    sw_q_state[i]->SetDownCoreID(DEFAULT_INVALID_CORE_ID);
    sw_q_state[i]->sw_q = sw_q[i];
    sw_q_state[i]->sw_batch = reinterpret_cast<bess::PacketBatch *>
        (std::aligned_alloc(alignof(bess::PacketBatch), sizeof(bess::PacketBatch)));
    sw_q_state[i]->sw_batch->clear();
    sw_q_state[i]->sw_q_id = i;
    sw_q_state[i]->idle_epoch_count = -2;
    sw_q_state[i]->assigned_packet_count = 0;
    sw_q_state[i]->processed_packet_count = 0;
  }

  for (int i = 0; i < DEFAULT_NICQ_COUNT; i++) {
    // |local_mc_q| is used by all Metron / Quadrant cores to receive tagged packets.
    // mp: many software switch cores; sc: each worker core pulls from its own queue.
    local_mc_q[i] = reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));
    ret = llring_init(local_mc_q[i], sw_qsize, 0, 1);
    if (ret) {
      std::free(local_mc_q[i]);
      LOG(FATAL) << "llring_init failed on local boost queue " << i;
      break;
    }
  }

  // Assign a system-level rcore booster core and a dump queue.
  size_t dump_qsize = DEFAULT_DUMPQ_SIZE;
  bytes = llring_bytes_with_slots(dump_qsize);

  rcore_boost_q = reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));
  if (rcore_boost_q) {
    llring_init(rcore_boost_q, dump_qsize, 0, 1);
  } else {
    std::free(rcore_boost_q);
    LOG(FATAL) << "failed to allocate rcore_boost_q";
  }
  rcore_booster_q_state = reinterpret_cast<SoftwareQueueState*>(
        std::aligned_alloc(alignof(SoftwareQueueState), sizeof(SoftwareQueueState)));
  rcore_booster_q_state->sw_q = rcore_boost_q;
  rcore_booster_q_state->sw_batch = reinterpret_cast<bess::PacketBatch *>
        (std::aligned_alloc(alignof(bess::PacketBatch), sizeof(bess::PacketBatch)));

  system_dump_q = reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));
  if (system_dump_q) {
    llring_init(system_dump_q, dump_qsize, 0, 1);
  } else {
    std::free(system_dump_q);
    LOG(FATAL) << "failed to allocate system_dump_q";
  }
  system_dump_q_state = reinterpret_cast<SoftwareQueueState*>(
        std::aligned_alloc(alignof(SoftwareQueueState), sizeof(SoftwareQueueState)));
  system_dump_q_state->sw_q = system_dump_q;
  system_dump_q_state->sw_batch = reinterpret_cast<bess::PacketBatch *>
        (std::aligned_alloc(alignof(bess::PacketBatch), sizeof(bess::PacketBatch)));

  LOG(INFO) << "NFV control messages are initialized";
}

void NFVCtrlMsgDeInit() {
  SoftwareQueueState *q_state = nullptr;
  bess::Packet *pkt = nullptr;
  struct llring *q = nullptr;

  for (int i = 0; i < DEFAULT_LOCALQ_COUNT; i++) {
    q = local_q[i];
    if (q) {
      while (llring_sc_dequeue(q, (void **)&pkt) == 0) {
        bess::Packet::Free(pkt);
      }
      std::free(q);
    }

    q = local_boost_q[i];
    if (q) {
      while (llring_sc_dequeue(q, (void **)&pkt) == 0) {
        bess::Packet::Free(pkt);
      }
      std::free(q);
    }
  }

  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    q = sw_q[i];
    if (q) {
      while (llring_sc_dequeue(q, (void **)&pkt) == 0) {
        bess::Packet::Free(pkt);
      }
      std::free(q);
    }

    q_state = sw_q_state[i];
    if (q_state) {
      std::free(q_state);
    }
  }

  for (int i = 0; i < DEFAULT_NICQ_COUNT; i++) {
    q = local_mc_q[i];
    if (q) {
      while (llring_sc_dequeue(q, (void **)&pkt) == 0) {
        bess::Packet::Free(pkt);
      }
      std::free(q);
    }
  }

  if (rcore_boost_q) {
    while (llring_sc_dequeue(rcore_boost_q, (void **)&pkt) == 0) {
      bess::Packet::Free(pkt);
    }
    std::free(rcore_boost_q);
    rcore_boost_q = nullptr;
  }

  if (system_dump_q) {
    while (llring_sc_dequeue(system_dump_q, (void **)&pkt) == 0) {
      bess::Packet::Free(pkt);
    }
    std::free(system_dump_q);
    system_dump_q = nullptr;
  }

  LOG(INFO) << "NFV control messages are de-initialized";
}

void NFVCtrlCheckAllComponents() {
  if (nfv_ctrl == nullptr || pmd_port == nullptr) {
    return;
  }
  nfv_ctrl->InitPMD(pmd_port);
}

// Transfer the ownership of (at most) |n| software packet queues
// to NFVCore (who calls this function)
std::vector<int> NFVCtrlRequestNSwQ(cpu_core_t core_id, int n) {
  if (nfv_cores[core_id] == nullptr) {
    LOG(FATAL) << "Core " << core_id << " is used but not created";

    // To register all normal CPU cores
    for (int i = 0; i < DEFAULT_INVALID_CORE_ID; i++){
      std::string core_name = "nfv_core" + std::to_string(i);
      for (const auto &it : ModuleGraph::GetAllModules()) {
        if (it.first.find(core_name) != std::string::npos) {
          nfv_cores[i] = ((NFVCore *)(it.second));
        }
      }
    }
  }

  if (nfv_ctrl == nullptr) {
    LOG(FATAL) << "NFVCtrl is used but not created";
    std::vector<int> assigned;
    return assigned;
  }

  return nfv_ctrl->RequestNSwQ(core_id, n);
}

void NFVCtrlReleaseNSwQ(cpu_core_t core_id, std::vector<int> q_ids) {
  nfv_ctrl->ReleaseNSwQ(core_id, q_ids);
}

int NFVCtrlNotifyRCoreToWork(cpu_core_t core_id, int q_id) {
  if (nfv_ctrl == nullptr) {
    return -1;
  }
  return nfv_ctrl->NotifyRCoreToWork(core_id, q_id);
}

int NFVCtrlNotifyRCoreToRest(cpu_core_t core_id, int q_id) {
  if (nfv_ctrl == nullptr) {
    return -1;
  }
  return nfv_ctrl->NotifyRCoreToRest(core_id, q_id);
}

} // namespace ctrl
} // namespace bess
