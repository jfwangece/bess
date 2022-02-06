#ifndef BESS_UTILS_SYS_MEASURE_H_
#define BESS_UTILS_SYS_MEASURE_H_

#include <vector>

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

} // namespace utils
} // namespace bess

#endif
