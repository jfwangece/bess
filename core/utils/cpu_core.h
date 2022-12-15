#ifndef BESS_UTILS_CPU_CORE_H
#define BESS_UTILS_CPU_CORE_H

#include <cstdint>

#include "flow.h"

typedef uint16_t cpu_core_t;

namespace bess{
namespace utils {

// This struct represents an active worker core
// |core_id|: the unique CPU core ID number
// |worker_port|, |nic_addr|: routing information
// |active_flows|: a set of active flows assigned to this core
struct WorkerCore {
  WorkerCore() = default;
  WorkerCore(int core, int port, std::string addr) {
    core_id = core; worker_port = port; nic_addr = addr;
    active_flow_count = 0; packet_rate = 0; idle_period_count = 0;
    per_flow_packet_counter.clear();
  };

  // Core info
  cpu_core_t core_id;
  int worker_port;
  std::string nic_addr;

  // Traffic statistics
  uint32_t active_flow_count;
  uint32_t packet_rate;
  uint32_t idle_period_count;
  uint64_t p99_latency;

  // Timestamp
  uint64_t last_migrating_ts_ns_;

  // Flow statistics
  std::unordered_map<Flow, uint64_t, FlowHash> per_flow_packet_counter;
};

} // namespace utils
} // namespace bess

#endif // BESS_UTILS_CPU_CORE_H
