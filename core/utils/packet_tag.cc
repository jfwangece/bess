#include "packet_tag.h"

#include <chrono>

namespace bess{
namespace utils{
namespace {
std::string CurrentDate() {
  using sysclock_t = std::chrono::system_clock;
  std::time_t now = sysclock_t::to_time_t(sysclock_t::now());
  char buf[16] = {0};
  std::strftime(buf, sizeof(buf), "%Y-%m-%d", std::localtime(&now));
  return std::string(buf);
}
} // namespace

void LogPacketTags(std::vector<PerPacketTag> tags) {
  std::string now = CurrentDate();
  std::string fname = "tags-" + now + ".txt";
  std::ofstream out_fp(fname);
  if (out_fp.is_open()) {
    for (size_t i = 0; i < tags.size(); i++) {
      out_fp << "packet:" << i;
      out_fp << "idle:" << tags[i].rcore_idle_epoch_count;
      out_fp << ", qlen:" << tags[i].sw_q_len;
      out_fp << std::endl;
    }
  }
  out_fp.close();
}

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

void TagPacketTimestamp(bess::Packet* pkt, size_t offset, uint64_t ts) {
  TagUint64(pkt, offset, ts);
}

void GetPacketTimestamp(bess::Packet* pkt, size_t offset, uint64_t *ts) {
  GetUint64(pkt, offset, ts);
}
} // namespace utils
} // namespace bess
