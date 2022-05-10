#include "packet_tag.h"

namespace bess{
namespace utils{
void TagPacketTimestamp(bess::Packet* pkt, size_t offset, uint64_t ts) {
  uint64_t* ts_ptr;
  const size_t kTagSize = sizeof(*ts_ptr);
  size_t room = pkt->data_len() - offset;
  if (room < kTagSize) {
    void *ret = pkt->append(kTagSize - room);
    if (!ret) {
      // not enough tailroom for timestamp. give up
      return;
    }
  }
  ts_ptr = pkt->head_data<uint64_t *>(offset);
  *ts_ptr = ts;
}

void GetPacketTimestamp(bess::Packet* pkt, size_t offset, uint64_t *ts) {
  *ts = *(pkt->head_data<uint64_t *>(offset));
}
} // namespace utils
} // namespace bess
