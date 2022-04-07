#ifndef BESS_MODULES_NFV_CTRL_MSG_H_
#define BESS_MODULES_NFV_CTRL_MSG_H_

#include "../utils/cpu_core.h"

// Number of software packet queues
#define DEFAULT_SWQ_COUNT 40

// |SoftwareQueue| tracks the mapping of (NFVCore, sw_q, NFVRCore)
class SoftwareQueue {
 public:
  SoftwareQueue() {
    up_core_id = down_core_id = DEFAULT_INVALID_CORE_ID;
  }

  cpu_core_t up_core_id;
  cpu_core_t down_core_id;
};

// Forward declaration
class NFVCtrl;
class NFVCore;
class NFVRCore;

// The only instance of NFVCtrl on this worker
extern NFVCtrl* nfv_ctrl;

extern NFVCore* nfv_cores[DEFAULT_INVALID_CORE_ID];

extern NFVRCore* nfv_rcores[DEFAULT_INVALID_CORE_ID];

// Note: only NFVCtrl can access data structures below

// A pool of software packet queues
extern struct llring* sw_q[DEFAULT_SWQ_COUNT];

// States for maintaining software packet queues, reserved cores.
extern SoftwareQueue* sw_q_state[DEFAULT_SWQ_COUNT];
extern bool rcore_state[DEFAULT_INVALID_CORE_ID];

// Request |n| software queues from the global software queue pool.
// The return value is a bit-mask that records the assignment of
// software queues: if (1 << i) is set, then sw_q[i] is assigned.
uint64_t NFVCtrlRequestNSwQ(cpu_core_t core_id, int n);

// Release software queues according to |q_mask|.
// Note: a sw_q goes back to the pool only if core |core_id| owns it.
void NFVCtrlReleaseNSwQ(cpu_core_t core_id, uint64_t q_mask);

// Request a reserved core to work on the software queue |q_id|.
// Return true if an idle reserved core is found.
bool NFVCtrlNotifyRCoreToWork(cpu_core_t core_id, int q_id);

// If sw_q |q_id| is currently handled by a reserved core.
// This function will un-schedule the NFVRCore and make it idle.
// Afterwards, the NFVRCore is ready to handle another sw_q.
void NFVCtrlNotifyRCoreToRest(cpu_core_t core_id, int q_id);

#endif // BESS_MODULES_NFV_CTRL_MSG_H_
