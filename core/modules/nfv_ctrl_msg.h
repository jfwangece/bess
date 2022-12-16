#ifndef BESS_MODULES_NFV_CTRL_MSG_H_
#define BESS_MODULES_NFV_CTRL_MSG_H_

#include "../drivers/pmd.h"
#include "../utils/cpu_core.h"
#include "../utils/flow.h"
#include "../utils/lock_less_queue.h"

#include <mutex>
#include <vector>

using bess::utils::Flow;

// Quadrant
#define WorkerDelayTsTagOffset 100

// Number of NFV workers in a cluster
#define DEFAULT_INVALID_WORKER_ID 10

// Valid Core ID range [0, 63]
#define DEFAULT_INVALID_CORE_ID 40
#define DEFAULT_NFVCTRL_CORE_ID (DEFAULT_INVALID_CORE_ID-1)

// Number of software packet queues
#define DEFAULT_LOCALQ_COUNT 10
#define DEFAULT_SWQ_COUNT 100
#define DEFAULT_NICQ_COUNT 40

// Default queue size
#define DEFAULT_SWQ_SIZE 1024
#define DEFAULT_DUMPQ_SIZE 4096

// Forward declaration
struct llring;
class NFVCtrl;
class NFVCore;
class NFVRCore;
class NFVMonitor;
class MetronCore;
class Measure;

namespace bess {
namespace ctrl {

/// States for maintaining software packet queues, normal and reserved cores.
// |SoftwareQueueState| tracks the mapping of (NFVCore, sw_q, NFVRCore)
// |sw_q|: the software queue's pointer;
// |sw_q_id|: the global software queue index seen by NFVCtrl.
// |assigned_packet_count|: the number of packets to be enqueued;
// |processed_packet_count|: the number of packets seen by the queue;
// |idle_epoch_count|: the number of epoches with no packet arrivals;
struct SoftwareQueueState {
  SoftwareQueueState() = default;

  // Atomic assignment functions
  void SetUpCoreID(uint16_t core_id) { rte_atomic16_set(&up_core_id, (int16_t)core_id); }
  void SetDownCoreID(uint16_t core_id) { rte_atomic16_set(&down_core_id, (int16_t)core_id); }
  uint16_t GetUpCoreID() { return (uint16_t)rte_atomic16_read(&up_core_id); }
  uint16_t GetDownCoreID() { return (uint16_t)rte_atomic16_read(&down_core_id); }

  // Non atomic states
  inline bool IsIdle() {
    return idle_epoch_count == -2;
  }
  inline bool IsTerminating() {
    return idle_epoch_count == -1;
  }
  inline bool IsActive() {
    return idle_epoch_count >= 0;
  }
  inline uint32_t QLenAfterAssignment() {
    return assigned_packet_count;
  }

  rte_atomic16_t up_core_id;
  rte_atomic16_t down_core_id;

  struct llring* sw_q;
  bess::PacketBatch* sw_batch;
  int sw_q_id;
  int idle_epoch_count; // -2: idle; -1: terminating; 0 and 0+: active
  uint32_t assigned_packet_count;
  uint32_t processed_packet_count;
};

struct FlowState {
  FlowState() {
    rss = 0;
    short_epoch_packet_count = 0;
    queued_packet_count = 0;
    enqueued_packet_count = 0;
    sw_q_state = nullptr;
  }

  Flow flow; // for long-term flow counter
  uint32_t rss; // NIC's RSS-based hash for |flow|
  uint32_t short_epoch_packet_count; // short-term epoch packet counter
  uint32_t queued_packet_count; // packet count in the system
  uint32_t enqueued_packet_count; // packet count in the SplitAndEnqueue process
  SoftwareQueueState *sw_q_state; // |this| flow sent to software queue w/ valid |sw_q_state|
};

// Used in measure, ironside_ingress
extern std::shared_mutex nfvctrl_worker_mu;
// Used in nfvctrl, nfv_core
extern std::shared_mutex nfvctrl_bucket_mu;

// The only instance of NFVCtrl on this worker
extern NFVCtrl* nfv_ctrl;

// Ironside
extern NFVCore* nfv_cores[DEFAULT_INVALID_CORE_ID];
extern NFVRCore* nfv_booster[DEFAULT_INVALID_CORE_ID];
extern NFVRCore* nfv_rcores[DEFAULT_INVALID_CORE_ID];
extern NFVRCore* nfv_rcore_booster;
extern NFVRCore* nfv_system_dumper;

extern NFVMonitor* nfv_monitors[DEFAULT_INVALID_CORE_ID];

extern MetronCore* metron_cores[DEFAULT_INVALID_CORE_ID];

extern Measure* sys_measure;

extern PMDPort* pmd_port;

// An integer number that identifies an Ironside's experiment.
// 0: normal run;
// 1: profiling run;
// 2: Metron run;
// 3: Quadrant run;
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
extern struct llring* rcore_boost_q; // to boost rcores
extern struct llring* system_dump_q; // to drop

extern struct llring* local_q[DEFAULT_LOCALQ_COUNT]; // for ncores
extern struct llring* local_boost_q[DEFAULT_LOCALQ_COUNT]; // to boost ncores

extern struct llring* sw_q[DEFAULT_SWQ_COUNT]; // for rcores

extern struct llring* local_mc_q[DEFAULT_NICQ_COUNT]; // for metron / quadrant

/// Worker-layer core mapping
extern int ncore;
extern int rcore;

// Performance states
extern uint64_t pc_max_batch_delay[100]; // Quadrant

extern uint64_t pcpb_packet_count[DEFAULT_INVALID_CORE_ID][512]; // Ironside
extern uint64_t pcpb_flow_count[DEFAULT_INVALID_CORE_ID][512]; // Ironside

extern SoftwareQueueState* sw_q_state[DEFAULT_SWQ_COUNT];
extern SoftwareQueueState* rcore_booster_q_state;
extern SoftwareQueueState* system_dump_q_state;

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
void NFVCtrlReleaseNSwQ(cpu_core_t core_id, std::vector<int> q_ids);

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
