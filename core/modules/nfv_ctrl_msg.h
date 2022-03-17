#ifndef BESS_MODULES_NFV_CTRL_MSG_H_
#define BESS_MODULES_NFV_CTRL_MSG_H_

// Valid Core ID range [0, 63]
#define DEFAULT_INVALID_CORE_ID 64

// Number of software packet queues
#define DEFAULT_SWQ_COUNT 40

class SoftwareQueue {
 public:
  SoftwareQueue() {
    state = 0; up_core_id = down_core_id = DEFAULT_INVALID_CORE_ID;
  }

 private:
  uint16_t state;
  uint16_t up_core_id;
  uint16_t down_core_id;
  uint16_t unused;
};

// The only instance of NFVCtrl on this worker
extern NFVCtrl* nfv_ctrl;

// A pool of software packet queues
extern struct llring* sw_q[DEFAULT_SWQ_COUNT];

// A pool of atomic variables for all software packet queues
extern rte_atomic16_t* sw_q_state[DEFAULT_SWQ_COUNT];

#endif // BESS_MODULES_NFV_CTRL_MSG_H_
