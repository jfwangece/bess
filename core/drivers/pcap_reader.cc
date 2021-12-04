#include "pcap.h"
#include "pcap_reader.h"

#include <string>

namespace {
const int kDefaultTagOffset = 64;

struct pcap_pkthdr pkthdr_;

static inline void tag_packet(bess::Packet *pkt, size_t offset,
                              uint32_t tsec, uint32_t tusec) {
  uint32_t *ts;
  const size_t kTagSize = sizeof(*ts) * 2;
  size_t room = pkt->data_len() - offset;

  if (room < kTagSize) {
    void *ret = pkt->append(kTagSize - room);
    if (!ret) {
      // not enough tailroom for timestamp. give up
      return;
    }
  }

  ts = pkt->head_data<uint32_t *>(offset);
  *ts = tsec;
  ts += 1;
  *ts = tusec;
}
} // namespace

CommandResponse PCAPReader::Init(const bess::pb::PCAPReaderArg& arg) {
  // whether record the per-packet timestamp in the per-packet metadata.
  if (arg.timestamp()) {
    is_timestamp_ = true;
  }
  const std::string dev = arg.dev();
  char msg_buf[PCAP_ERRBUF_SIZE];
  pcap_handle_ = pcap_open_offline(dev.c_str(), msg_buf);

  if (pcap_handle_ == nullptr) {
    return CommandFailure(EINVAL, "Error initializing the pcap handle.");
  }

  return CommandSuccess();
}

void PCAPReader::DeInit() {
  pcap_close(pcap_handle_);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

int PCAPReader::RecvPackets(queue_t qid, bess::Packet** pkts, int cnt) {
  if (pcap_handle_ == nullptr) {
    return 0;
  }

  int recv_cnt = 0;

  DCHECK_EQ(qid, 0);

  while(recv_cnt < cnt) {
    int caplen = 0;
    // read one packet from the pcap file
    pkt_ = pcap_next(pcap_handle_, &pkthdr_);
    if (!pkt_) {
      break;
    }
    caplen = pkthdr_.len;

alloc:
    bess::Packet* pkt = current_worker.packet_pool()->Alloc();
    if (!pkt) {
      goto alloc;
    }

    if (is_timestamp_) {
      uint32_t tsec = pkthdr_.ts.tv_sec & 0xFFFFFFFF;
      uint32_t tusec = pkthdr_.ts.tv_usec & 0xFFFFFFFF;
      tag_packet(pkt, 64, tsec, tusec);
    }

    int copy_len = std::min(caplen, static_cast<int>(pkt->tailroom()));
    bess::utils::CopyInlined(pkt->append(copy_len), pkt_, copy_len, true);

    pkt_ += copy_len;
    caplen -= copy_len;
    bess::Packet* m = pkt;

    int nb_segs = 1;
    while (caplen > 0) {
      m->set_next(current_worker.packet_pool()->Alloc());
      m = m->next();
      nb_segs++;

      copy_len = std::min(caplen, static_cast<int>(m->tailroom()));
      bess::utils::Copy(m->append(copy_len), pkt_, copy_len, true);

      pkt_ += copy_len;
      caplen -= copy_len;
    }
    pkt->set_nb_segs(nb_segs);
    pkts[recv_cnt] = pkt;
    recv_cnt++;
    pkt_counter_++;
  }

  return recv_cnt;
}

int PCAPReader::SendPackets(queue_t, bess::Packet** pkts, int cnt) {
  if (pcap_handle_ == nullptr) {
    CHECK(0);  // raise an error
  }

  return 0;
}

ADD_DRIVER(PCAPReader, "pcap_reader", "libpcap packet reader from a pcap file")

#pragma GCC diagnostic pop
