#include "nfv_ctrl.h"
#include "nfv_ctrl_msg.h"
#include "nfv_core.h"
#include "nfv_rcore.h"
#include "nfv_monitor.h"

#include "../module_graph.h"

#include <mutex>

/// Initialize global NFV control messages
namespace bess {
namespace ctrl {

NFVCtrl* nfv_ctrl = nullptr;

NFVCore* nfv_cores[DEFAULT_INVALID_CORE_ID] = {nullptr};

NFVRCore* nfv_rcores[DEFAULT_INVALID_CORE_ID] = {nullptr};

PMDPort* pmd_port = nullptr;

std::mutex nfvctrl_mu;

struct llring* sw_q[DEFAULT_SWQ_COUNT] = {nullptr};

SoftwareQueue* sw_q_state[DEFAULT_SWQ_COUNT] = {nullptr}; // sw_q can be assigned if |up_core_id| is invalid

bool core_state[DEFAULT_INVALID_CORE_ID] = {false}; // core is in-use if true

bool rcore_state[DEFAULT_INVALID_CORE_ID] = {false}; // rcore can be assigned if true

int core_liveness[DEFAULT_INVALID_CORE_ID] = {0}; // the number of long epochs in which a core has been live

// Global software queue / reserved core management functions

void NFVCtrlMsgInit(int slots) {
  int bytes = llring_bytes_with_slots(slots);
  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    sw_q[i] = reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));

    int ret = llring_init(sw_q[i], slots, 1, 1);
    if (ret) {
      std::free(sw_q[i]);
      LOG(ERROR) << "llring_init failed on software queue " << i;
      break;
    }

    // Note: each SoftwareQueue object has to be initialized as
    // 'rte_malloc' does not initialize it when allocating memory
    sw_q_state[i] =
        reinterpret_cast<SoftwareQueue *>(
        std::aligned_alloc(alignof(SoftwareQueue), sizeof(SoftwareQueue)));
    sw_q_state[i]->up_core_id = DEFAULT_INVALID_CORE_ID;
    sw_q_state[i]->down_core_id = DEFAULT_INVALID_CORE_ID;
  }

  LOG(INFO) << "NFV control messages are initialized";
}

void NFVCtrlMsgDeInit() {
  struct llring *q = nullptr;
  SoftwareQueue *q_state = nullptr;
  bess::Packet *pkt = nullptr;

  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    q = sw_q[i];
    if (q) {
      while (llring_sc_dequeue(q, (void **)&pkt) == 0) {
        bess::Packet::Free(pkt);
      }
      std::free(q);
    }
    q = nullptr;

    q_state = sw_q_state[i];
    if (q_state) {
      std::free(q_state);
    }
    q_state = nullptr;
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
uint64_t NFVCtrlRequestNSwQ(cpu_core_t core_id, int n) {
  if (nfv_cores[core_id] == nullptr) {
    LOG(ERROR) << "Core " << core_id << " is used but not created";
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
    LOG(ERROR) << "NFVCtrl is used but not created";
    return 0;
  }

  return nfv_ctrl->RequestNSwQ(core_id, n);
}

void NFVCtrlReleaseNSwQ(cpu_core_t core_id, uint64_t q_mask) {
  nfv_ctrl->ReleaseNSwQ(core_id, q_mask);
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
