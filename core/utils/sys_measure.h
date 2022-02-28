#ifndef BESS_UTILS_SYS_MEASURE_H_
#define BESS_UTILS_SYS_MEASURE_H_

#include <cstdint>
#include <vector>

#include "flow.h"
#include "lock_less_queue.h"

namespace bess{
namespace utils {

// This struct represents an active worker core
// |core_id|: the unique CPU core ID number
// |worker_port|, |nic_addr|: routing information
// |active_flows|: a set of active flows assigned to this core
struct WorkerCore {
  WorkerCore(int core, int port, std::string addr) {
    core_id = core; worker_port = port; nic_addr = addr;
    active_flow_count = 0; packet_rate = 0; idle_period_count = 0;
    per_flow_packet_counter.clear();
  };

  // Core info
  int core_id;
  int worker_port;
  std::string nic_addr;
  // Traffic statistics
  int active_flow_count;
  float packet_rate;
  int idle_period_count;
  // Timestamp
  uint64_t last_migrating_ts_ns_;
  // Flow statistics
  std::unordered_map<Flow, uint64_t, FlowHash> per_flow_packet_counter;
};

struct Snapshot {
  Snapshot(int t_id) {
    epoch_id = t_id; active_core_count = 0; sum_packet_rate = 0;
  };

  int epoch_id; // Starting from 0
  int active_core_count; // Number of CPU cores with traffic
  float sum_packet_rate; // Sum of all CPU cores' packet rates
  std::vector<uint64_t> per_core_packet_rate;
};

struct CoreSnapshot {
  CoreSnapshot(int t_id) {
    epoch_id = t_id; active_flow_count = 0; packet_rate = 0.0;
  };

  int epoch_id; // Starting from 0
  int slo_violation; // Number of packets with SLO violations
  int active_flow_count; // Number of active flows
  int bursty_flow_count ; // Number of bursty flows
  float packet_rate; // Sum of a core's packet rate
};

// Per-core performance statistics for making LB decisions
class CoreStats {
 public:
  CoreStats() { packet_rate = 0; p99_latency = 0; }
  CoreStats(uint64_t r, uint64_t l) { packet_rate = r; p99_latency = l; }
  CoreStats(const CoreStats& cs) : CoreStats(cs.packet_rate, cs.p99_latency) {}

  uint64_t packet_rate;
  uint64_t p99_latency;
  std::vector<Flow> bursty_flows;
};

// Core statistics buffer
static std::vector<CoreStats> all_core_stats (20);

// Core statistics message channel
extern LockLessQueue<CoreStats*> *volatile all_core_stats_chan[20];

void SysMeasureInit();
void SysMeasureDeinit();

} // namespace utils
} // namespace bess

#endif
