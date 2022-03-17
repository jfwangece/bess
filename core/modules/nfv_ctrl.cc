#include "nfv_ctrl.h"
#include "nfv_ctrl_msg.h"
#include "nfv_monitor.h"

#include <chrono>
#include <thread>

#include "../module_graph.h"
#include "../utils/sys_measure.h"

namespace {
std::chrono::milliseconds DEFAULT_SLEEP_DURATION(100);
} // namespace

/// Initialize global NFV control messages

NFVCtrl *nfv_ctrl = nullptr;

struct llring* sw_q[DEFAULT_SWQ_COUNT];

rte_atomic16_t* sw_q_state[DEFAULT_SWQ_COUNT];

void NFVCtrlMsgInit(int slots) {
  int bytes = llring_bytes_with_slots(slots);
  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    sw_q[i] =
        reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));
  }
}

void NFVCtrlMsgDeInit() {
  struct llring *q = nullptr;
  bess::Packet *pkt = nullptr;

  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    q = sw_q[i];
    if (q) {
      while (llring_sc_dequeue(q, (void **)&pkt) == 0) {
        bess::Packet::Free(pkt);
      }
    }
    std::free(q);
    q = nullptr;
  }
}

// Transfer the ownership of (at most) |n| software packet queues
// to NFVCore (who calls this function)
uint64_t NFVCtrlRequestSwQ(int core_id, int n) {
  if (nfv_ctrl != nullptr) {
    return nfv_ctrl->RequestSwQ(core_id, n);
  }
  return 0;
}

/// NFVCtrl's own functions

const Commands NFVCtrl::cmds = {
    {"get_summary", "EmptyArg", MODULE_CMD_FUNC(&NFVCtrl::CommandGetSummary),
     Command::THREAD_SAFE},
};

uint64_t NFVCtrl::RequestSwQ(int core_id, int n) {
  if (core_id < 0) {
    return 0;
  }

  uint64_t q_bitmask = 0;
  int cnt = 0;
  for (int i = 0; i < DEFAULT_SWQ_COUNT; i++) {
    if (sw_q_state[i] ) {
      q_bitmask |= 1 << i;
    }
    if (cnt == n) {
      break;
    }
  }
  return q_bitmask;
}

CommandResponse NFVCtrl::Init(const bess::pb::NFVCtrlArg &arg) {
  nfv_ctrl = this;
  NFVCtrlMsgInit(1024);

  task_id_t tid = RegisterTask(nullptr);
  if (tid == INVALID_TASK_ID) {
    return CommandFailure(ENOMEM, "Task creation failed");
  }

  total_core_count_ = 0;
  for (const auto &core_addr : arg.core_addrs()) {
    cpu_cores_.push_back(
      WorkerCore {
        core_id: total_core_count_,
        worker_port: core_addr.l2_port(),
        nic_addr: core_addr.l2_mac()}
    );
  }
  assert(total_core_count_ == cpu_cores_.size());

  curr_ts_ns_ = 0;

  if (arg.slo_ns() > 0) {
    bess::utils::slo_ns = arg.slo_ns();
  }

  return CommandSuccess();
}

void NFVCtrl::DeInit() {
  nfv_ctrl = nullptr;
  NFVCtrlMsgDeInit();
}

CommandResponse NFVCtrl::CommandGetSummary([[maybe_unused]]const bess::pb::EmptyArg &arg) {
  for (const auto &it : ModuleGraph::GetAllModules()) {
    if (it.first.find("nfv_monitor") != std::string::npos) {
      ((NFVMonitor *)(it.second))->CommandGetSummary(arg);
    }
  }
  return CommandSuccess();
}

struct task_result NFVCtrl::RunTask(Context *ctx, bess::PacketBatch *batch, void *) {
  RunNextModule(ctx, batch); // To avoid [-Werror=unused-parameter] error
  return {.block = false, .packets = 0, .bits = 0};
}

void NFVCtrl::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  RunNextModule(ctx, batch); // To avoid [-Werror=unused-parameter] error
}

ADD_MODULE(NFVCtrl, "nfv_ctrl", "The per-worker NFV controller that interacts with NFVCore and NFVMonitor")
