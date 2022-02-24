#include "sys_measure.h"

namespace bess{
namespace utils {

LockLessQueue<CoreStats*> *volatile all_core_stats_chan[20];

void SysMeasureInit() {
  for (int i = 0; i < 20; i++) {
    all_core_stats_chan[i] = new LockLessQueue<CoreStats*>();
  }
}

void SysMeasureDeinit() {
  for (int i = 0; i < 20; i++) {
    delete all_core_stats_chan[i];
    all_core_stats_chan[i] = nullptr;
  }
}

} // namespace utils
} // namespace bess
