#ifndef BESS_UTILS_SYS_MEASURE_H_
#define BESS_UTILS_SYS_MEASURE_H_

#include <cstdint>
#include <vector>

#include "flow.h"
#include "lock_less_queue.h"

namespace bess{
namespace utils {

struct Snapshot {
  Snapshot(int t_id) {
    epoch_id = t_id; active_core_count = 0; sum_packet_rate = 0;
  };

  int epoch_id; // Starting from 0
  int active_core_count; // Number of CPU cores with traffic
  uint64_t sum_packet_rate; // Sum of all CPU cores' packet rates
  std::vector<uint64_t> per_core_packet_rate;
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
static std::vector<LockLessQueue<CoreStats *>> all_core_stats_chan (20);

} // namespace utils
} // namespace bess

#endif
