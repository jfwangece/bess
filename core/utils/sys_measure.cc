#include "sys_measure.h"

namespace bess{
namespace utils {

CoreStats *volatile all_local_core_stats[20];

LockLessQueue<CoreStats*> *volatile all_core_stats_chan[20];
uint64_t per_bucket_packet_counter[RETA_SIZE] = {0};
std::shared_mutex bucket_table_lock;
uint32_t rss_hash_to_id(uint32_t hash) {
  return hash & (RETA_SIZE-1);
}
uint32_t slo_ns = 1000000; // Default 1 ms

void SysMeasureInit() {
  for (int i = 0; i < 20; i++) {
    all_local_core_stats[i] = new CoreStats();

    all_core_stats_chan[i] = new LockLessQueue<CoreStats*>();    
  }
}

void SysMeasureDeinit() {
  for (int i = 0; i < 20; i++) {
    delete all_local_core_stats[i];
    all_local_core_stats[i] = nullptr;

    delete all_core_stats_chan[i];
    all_core_stats_chan[i] = nullptr;
  }
}

} // namespace utils
} // namespace bess
