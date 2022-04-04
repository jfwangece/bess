#ifndef BESS_MODULES_NFV_CTRL_MSG_H_
#define BESS_MODULES_NFV_CTRL_MSG_H_

#include "../utils/cpu_core.h"

// Number of software packet queues
#define DEFAULT_SWQ_COUNT 40

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

uint64_t NFVCtrlRequestSwQ(cpu_core_t core_id, int n);

#endif // BESS_MODULES_NFV_CTRL_MSG_H_
