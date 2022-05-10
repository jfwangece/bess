#ifndef BESS_UTILS_PACKET_TAG_H_
#define BESS_UTILS_PACKET_TAG_H_

#include "../packet.h"

namespace bess{
namespace utils{
struct PerPacketTag {
  PerPacketTag() = default;
  int rcore_idle_epoch_count;
  uint32_t sw_q_len;
};

void LogPacketTags(std::vector<PerPacketTag> tags);

inline void TagUint64(bess::Packet* pkt, size_t offset, uint64_t val);
inline void TagUint32(bess::Packet* pkt, size_t offset, uint32_t val);
inline void GetUint64(bess::Packet* pkt, size_t offset, uint64_t *val);
inline void GetUint32(bess::Packet* pkt, size_t offset, uint32_t *val);

// Tag a timestamp to |pkt| at |offset| (in bytes)
void TagPacketTimestamp(bess::Packet* pkt, size_t offset, uint64_t ts);

// Read the timestamp from |pkt| at |offset| (in bytes)
void GetPacketTimestamp(bess::Packet* pkt, size_t offset, uint64_t *ts);
} // namespace utils
} // namespace bess

#endif