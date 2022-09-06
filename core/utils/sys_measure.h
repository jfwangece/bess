#ifndef BESS_UTILS_SYS_MEASURE_H_
#define BESS_UTILS_SYS_MEASURE_H_

#include <cstdint>
#include <vector>
#include <shared_mutex>

#include "flow.h"
#include "lock_less_queue.h"

#define RETA_SIZE 512
namespace bess{
namespace utils {

struct Snapshot {
  Snapshot(int t_id) {
    epoch_id = t_id; active_core_count = 0; sum_packet_rate = 0;
  };

  int epoch_id; // Starting from 0
  uint32_t active_core_count; // Number of CPU cores with traffic
  uint32_t sum_packet_rate; // Sum of all CPU cores' packet rates
  std::vector<uint32_t> per_core_packet_rate;
};

struct CoreSnapshot {
  CoreSnapshot(int t_id) {
    epoch_id = t_id;
    slo_violation = 0; packet_delay_error = 0; packet_delay_max = 0;
    active_flow_count = 0; bursty_flow_count = 0;
    packet_rate = 0; packet_processed = 0; packet_queued = 0;
  };

  int epoch_id; // Starting from 0
  uint32_t epoch_size;
  uint16_t slo_violation; // Number of packets with SLO violations
  uint16_t packet_delay_error; // Number of packets with a wrong timestamp
  uint16_t packet_delay_max; // Max per-packet latency
  uint16_t active_flow_count; // Number of active flows
  uint16_t bursty_flow_count ; // Number of bursty flows
  uint16_t packet_rate; // Sum of a core's packet rate
  uint16_t packet_processed; // A core's total processed packets
  uint16_t packet_queued; // A NIC queue's total queued packets
};

// Per-core performance statistics for making LB decisions
class CoreStats {
 public:
  CoreStats() { active_flow_count = 0; packet_rate = 0; packet_processed = 0; packet_queued = 0; p99_latency = 0; }
  CoreStats(uint32_t af, uint32_t pr, uint32_t pp, uint32_t pq, uint64_t l) {
    active_flow_count = af;
    packet_rate = pr; packet_processed = pp; packet_queued = pq;
    p99_latency = l;
  }
  CoreStats(const CoreStats& cs) :
    CoreStats(cs.active_flow_count, cs.packet_rate, cs.packet_processed, cs.packet_queued, cs.p99_latency) {}

  uint16_t active_flow_count;
  uint16_t packet_rate;
  uint16_t packet_processed;
  uint16_t packet_queued;
  uint64_t p99_latency;
  std::vector<Flow> bursty_flows;
};

class BucketStats {
 public:
  BucketStats() {}
  uint32_t RSSHashToID(uint32_t hash) {
    return hash & (RETA_SIZE-1);
  }

  uint64_t per_bucket_packet_counter[RETA_SIZE] = {0};
  std::unordered_map<Flow, bool, FlowHash> per_bucket_flow_cache[RETA_SIZE];
  std::shared_mutex bucket_table_lock;
};

// Used to maintain packet counts per RSS bucket
extern BucketStats *volatile bucket_stats;

// Core statistics buffer
extern CoreStats *volatile all_local_core_stats[20];

// Core statistics message channel
extern LockLessQueue<CoreStats*> *volatile all_core_stats_chan[20];

// Target latency SLO
extern uint32_t slo_ns;

// Add debug tag;
extern bool add_debug_tag_nfvcore;
extern bool add_debug_tag_nfvrcore;

void SysMeasureInit();
void SysMeasureDeinit();

} // namespace utils
} // namespace bess

#endif
