#ifndef BESS_MODULES_NFV_CTRL_MSG_H_
#define BESS_MODULES_NFV_CTRL_MSG_H_

#include "../drivers/pmd.h"
#include "../utils/cpu_core.h"

// Number of software packet queues
#define DEFAULT_SWQ_COUNT 80

// Forward declaration
struct llring;
class NFVCtrl;
class NFVCore;
class NFVRCore;
class NFVMonitor;

namespace bess {
namespace ctrl {

// |SoftwareQueue| tracks the mapping of (NFVCore, sw_q, NFVRCore)
class SoftwareQueue {
 public:
  SoftwareQueue() {
    up_core_id = down_core_id = DEFAULT_INVALID_CORE_ID;
  }

  cpu_core_t up_core_id;
  cpu_core_t down_core_id;
};

// The only instance of NFVCtrl on this worker
extern NFVCtrl* nfv_ctrl;

extern NFVCore* nfv_cores[DEFAULT_INVALID_CORE_ID];

extern NFVRCore* nfv_rcores[DEFAULT_INVALID_CORE_ID];

extern NFVMonitor* nfv_monitors[DEFAULT_INVALID_CORE_ID];

extern PMDPort *pmd_port;

//static int ready_components = 0;

// Note: only NFVCtrl can access data structures below

// A pool of software packet queues
extern struct llring* system_dump_q_;
extern struct llring* sw_q[DEFAULT_SWQ_COUNT];

// States for maintaining software packet queues, normal and reserved cores.
extern SoftwareQueue* sw_q_state[DEFAULT_SWQ_COUNT];
extern bool core_state[DEFAULT_INVALID_CORE_ID];
extern bool rcore_state[DEFAULT_INVALID_CORE_ID];
extern int core_liveness[DEFAULT_INVALID_CORE_ID];

// Create software queues and reset flags
void NFVCtrlMsgInit(int slots);
void NFVCtrlMsgDeInit();

// Check if all NFV components are ready. If yes:
// 1) initialize all management data;
// 2) update NIC RSS;
// 3) start the long-term optimization;
void NFVCtrlCheckAllComponents();

// Request |n| software queues from the global software queue pool.
// The return value is a bit-mask that records the assignment of
// software queues: if (1 << i) is set, then sw_q[i] is assigned.
uint64_t NFVCtrlRequestNSwQ(cpu_core_t core_id, int n);

// Release software queues according to |q_mask|.
// Note: a sw_q goes back to the pool only if core |core_id| owns it.
void NFVCtrlReleaseNSwQ(cpu_core_t core_id, uint64_t q_mask);

// Request a reserved core to work on the software queue |q_id|.
// Return 0 if an idle reserved core is found and notified to work.
int NFVCtrlNotifyRCoreToWork(cpu_core_t core_id, int q_id);

// If sw_q |q_id| is currently handled by a reserved core.
// This function will un-schedule the NFVRCore and make it idle.
// Afterwards, the NFVRCore is ready to handle another sw_q.
// Return 0 if the reserved core is released.
int NFVCtrlNotifyRCoreToRest(cpu_core_t core_id, int q_id);

} // namespace ctrl
} // namespace bess

#endif // BESS_MODULES_NFV_CTRL_MSG_H_
