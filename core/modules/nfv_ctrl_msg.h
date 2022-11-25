#ifndef BESS_MODULES_NFV_CTRL_MSG_H_
#define BESS_MODULES_NFV_CTRL_MSG_H_

#include "../drivers/pmd.h"
#include "../utils/cpu_core.h"

#include <mutex>
#include <vector>

// Number of NFV workers in a cluster
#define DEFAULT_INVALID_WORKER_ID 10

// Number of software packet queues
#define DEFAULT_LOCALQ_COUNT 10
#define DEFAULT_SWQ_COUNT 200
#define DEFAULT_NICQ_COUNT 40

// Default queue size
#define DEFAULT_SWQ_SIZE 1024;
#define DEFAULT_DUMPQ_SIZE 4096;

// Forward declaration
struct llring;
class NFVCtrl;
class NFVCore;
class NFVRCore;
class NFVMonitor;
class MetronCore;

namespace bess {
namespace ctrl {
// Used in measure, ironside_ingress
extern std::shared_mutex nfvctrl_worker_mu;
// Used in nfvctrl, nfv_core
extern std::shared_mutex nfvctrl_bucket_mu;

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

extern MetronCore* metron_cores[DEFAULT_INVALID_CORE_ID];

extern PMDPort *pmd_port;

// An integer number that identifies an Ironside's experiment.
// 0: normal run;
// 1: profiling run;
extern int exp_id;

// packet rate threshold given the flow count. Values are found using offline profiling
extern std::map<uint64_t, uint64_t> long_flow_count_pps_threshold;
extern std::map<uint32_t, uint32_t> short_flow_count_pkt_threshold;
extern std::map<uint16_t, uint16_t> trans_buckets;

/// ToR-layer core mapping (used in Ironside ingress)
// The number of in-use normal cores at each worker in the cluster.
extern int worker_ncore[DEFAULT_INVALID_WORKER_ID];
extern uint32_t worker_packet_rate[DEFAULT_INVALID_WORKER_ID];

// Note: only NFVCtrl can access data structures below

// A pool of software packet queues
extern struct llring* system_dump_q_;
extern struct llring* local_q[DEFAULT_LOCALQ_COUNT];
extern struct llring* local_boost_q[DEFAULT_LOCALQ_COUNT];
extern struct llring* sw_q[DEFAULT_SWQ_COUNT];
extern struct llring* local_mc_q[DEFAULT_NICQ_COUNT];

/// Worker-layer core mapping
extern int ncore;
extern int rcore;

// Performance states
extern uint64_t pcpb_packet_count[DEFAULT_INVALID_CORE_ID][512];
extern uint64_t pcpb_flow_count[DEFAULT_INVALID_CORE_ID][512];

// States for maintaining software packet queues, normal and reserved cores.
extern SoftwareQueue* sw_q_state[DEFAULT_SWQ_COUNT];
extern bool core_state[DEFAULT_INVALID_CORE_ID];
extern bool rcore_state[DEFAULT_INVALID_CORE_ID];
extern int core_liveness[DEFAULT_INVALID_CORE_ID];

// Create software queues and reset flags
void NFVCtrlMsgInit();
void NFVCtrlMsgDeInit();

// Check if all NFV components are ready. If yes:
// 1) initialize all management data;
// 2) update NIC RSS;
// 3) start the long-term optimization;
void NFVCtrlCheckAllComponents();

// Request |n| software queues from the global software queue pool.
// The return value is a bit-mask that records the assignment of
// software queues: if (1 << i) is set, then sw_q[i] is assigned.
std::vector<int> NFVCtrlRequestNSwQ(cpu_core_t core_id, int n);

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
