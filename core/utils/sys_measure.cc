#include "sys_measure.h"

namespace bess{
namespace utils {

BucketStats *volatile bucket_stats;
CoreStats *volatile all_local_core_stats[20];
LockLessQueue<CoreStats*> *volatile all_core_stats_chan[20];
uint32_t slo_ns = 1000000; // Default 1 ms

void SysMeasureInit() {
  bucket_stats = new BucketStats();
  for (int i = 0; i < 20; i++) {
    all_local_core_stats[i] = new CoreStats();
    all_core_stats_chan[i] = new LockLessQueue<CoreStats*>();    
  }
}

void SysMeasureDeinit() {
  delete bucket_stats;
  bucket_stats = nullptr;

  for (int i = 0; i < 20; i++) {
    delete all_local_core_stats[i];
    all_local_core_stats[i] = nullptr;

    delete all_core_stats_chan[i];
    all_core_stats_chan[i] = nullptr;
  }
}

} // namespace utils
} // namespace bess
