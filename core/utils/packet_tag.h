#ifndef BESS_UTILS_PACKET_TAG_H_
#define BESS_UTILS_PACKET_TAG_H_

#include "../packet.h"

namespace bess{
namespace utils{

// The debug information attached to each packet.
// |rcore_idle_epoch_count|: the number of idle epochs of the RCore,
// if the packet is redirected to a RCore;
// |sw_q_id|: software queue ID if pkt is redirected to a RCore;
// |sw_q_id|: software queue length if pkt is redirected to a RCore;
struct PerPacketTag {
  PerPacketTag() = default;
  uint32_t rcore_idle_epoch_count;
  uint32_t sw_q_id;
  uint32_t sw_q_len;
};

void LogPacketTags(std::vector<PerPacketTag> tags);

inline void TagUint64(bess::Packet* pkt, size_t offset, uint64_t val) {
  uint64_t* ptr;
  const size_t kTagSize = sizeof(*ptr);
  size_t room = pkt->data_len() - offset;
  if (room < kTagSize) {
    void *ret = pkt->append(kTagSize - room);
    if (!ret) {
      // not enough tailroom for timestamp. give up
      return;
    }
  }
  ptr = pkt->head_data<uint64_t*>(offset);
  *ptr = val;
}
inline void GetUint64(bess::Packet* pkt, size_t offset, uint64_t *val) {
  *val = *(pkt->head_data<uint64_t*>(offset));
}

inline void TagUint32(bess::Packet* pkt, size_t offset, uint32_t val) {
  uint32_t* ptr;
  const size_t kTagSize = sizeof(*ptr);
  size_t room = pkt->data_len() - offset;
  if (room < kTagSize) {
    void *ret = pkt->append(kTagSize - room);
    if (!ret) {
      // not enough tailroom for timestamp. give up
      return;
    }
  }
  ptr = pkt->head_data<uint32_t*>(offset);
  *ptr = val;
}
inline void GetUint32(bess::Packet* pkt, size_t offset, uint32_t *val) {
  *val = *(pkt->head_data<uint32_t*>(offset));
}

// Tag a timestamp to |pkt| at |offset| (in bytes)
void TagPacketTimestamp(bess::Packet* pkt, size_t offset, uint64_t ts);

// Read the timestamp from |pkt| at |offset| (in bytes)
void GetPacketTimestamp(bess::Packet* pkt, size_t offset, uint64_t *ts);

} // namespace utils
} // namespace bess

#endif