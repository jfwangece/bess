#ifndef BESS_UTILS_SYS_MEASURE_H_
#define BESS_UTILS_SYS_MEASURE_H_

#include "../packet.h"

namespace bess{
namespace utils{
// Tag a timestamp to |pkt| at |offset| (in bytes)
void TagPacketTimestamp(bess::Packet* pkt, size_t offset, uint64_t ts);

// Read the timestamp from |pkt| at |offset| (in bytes)
void GetPacketTimestamp(bess::Packet* pkt, size_t offset, uint64_t *ts);
} // namespace utils
} // namespace bess

#endif