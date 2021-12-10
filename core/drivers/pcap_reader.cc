#include "pcap.h"
#include "pcap_reader.h"

#include <string>

namespace {
const int kDefaultTagOffset = 64;

struct pcap_pkthdr pkthdr_;

static inline void tag_packet(bess::Packet *pkt, size_t offset,
                              uint64_t tusec) {
  uint64_t *ts;
  const size_t kTagSize = sizeof(*ts);
  size_t room = pkt->data_len() - offset;

  if (room < kTagSize) {
    void *ret = pkt->append(kTagSize - room);
    if (!ret) {
      // not enough tailroom for timestamp. give up
      return;
    }
  }

  ts = pkt->head_data<uint64_t *>(offset);
  *ts = tusec;
}
} // namespace

CommandResponse PCAPReader::Init(const bess::pb::PCAPReaderArg& arg) {
  // whether record the per-packet timestamp in the per-packet metadata.
  if (arg.timestamp()) {
    is_timestamp_ = true;
  }
  if (arg.offset()) {
    offset_ = arg.offset();
  } else {
    offset_ = kDefaultTagOffset;
  }
  const std::string dev = arg.dev();
  char msg_buf[PCAP_ERRBUF_SIZE];
  pcap_handle_ = pcap_open_offline(dev.c_str(), msg_buf);

  is_eth_missing_ = false;
  if (pcap_handle_ == nullptr) {
    return CommandFailure(EINVAL, "Error initializing the pcap handle.");
  } else {
    pkt_ = pcap_next(pcap_handle_, &pkthdr_);
    if (!pkt_) {
      return CommandFailure(EINVAL, "Error reading an empty pcap file.");
    }

    // Decide whether the Ethernet header has been removed
    is_eth_missing_ = *(uint16_t*)pkt_ == 0x0045 || *(uint16_t*)pkt_ == 0x0845 || *(uint16_t*)pkt_ == 0x4845 || *(uint16_t*)pkt_ == 0x0a14;

    init_tsec_ = pkthdr_.ts.tv_sec;
    init_tusec_ = pkthdr_.ts.tv_usec;
  }

  // Initialize payload template
  memset(tmpl_, 1, MAX_TEMPLATE_SIZE);
  // Initialize Ethernet header template
  eth_template_.src_addr = Ethernet::Address("ec:0d:9a:67:ff:68");
  eth_template_.dst_addr = Ethernet::Address("0a:14:69:37:5f:f2");
  eth_template_.ether_type = be16_t(Ethernet::Type::kIpv4);

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
    // read one packet from the pcap file
    pkt_ = pcap_next(pcap_handle_, &pkthdr_);
    if (!pkt_) {
      break;
    }
    int caplen = pkthdr_.caplen;
    int totallen = pkthdr_.len;

    if (is_eth_missing_) {
      totallen += sizeof(Ethernet);
    }
    // Maintain a minimal and a maximum packet size
    if (totallen > MAX_TEMPLATE_SIZE) {
      totallen = MAX_TEMPLATE_SIZE;
    }
    if (totallen < (int)offset_ + 8) {
      totallen = (int)offset_ + 8;
    }

alloc:
    bess::Packet* pkt = current_worker.packet_pool()->Alloc();
    if (!pkt) {
      goto alloc;
    }

    // Leave a headroom for prepending data
    char *p = pkt->buffer<char *>() + SNBUF_HEADROOM;
    pkt->set_data_off(SNBUF_HEADROOM);
    pkt->set_total_len(totallen);
    pkt->set_data_len(totallen);

    int total_copy_len = 0;
    int copy_len = 0;

    // Note: for NIC ether scoping, always use a fake Ethernet header
    Ethernet *eth = reinterpret_cast<Ethernet *>(p);
    eth->dst_addr = eth_template_.dst_addr;
    eth->src_addr = eth_template_.src_addr;
    eth->ether_type = eth_template_.ether_type;
    total_copy_len += sizeof(Ethernet);

    if (is_eth_missing_) {    
      copy_len = caplen;
      bess::utils::Copy(p + total_copy_len, pkt_, copy_len, true);
    } else {
      copy_len = caplen - sizeof(Ethernet);
      if (copy_len > 0) {
        bess::utils::Copy(p + total_copy_len, pkt_ + sizeof(Ethernet), copy_len, true);
      }
    }
    total_copy_len += copy_len;

    // Copy payload (not a necessary step)
    if (totallen > total_copy_len) {
      copy_len = totallen - total_copy_len;
      bess::utils::Copy(p + total_copy_len, tmpl_, copy_len, true);
      total_copy_len += copy_len;
    }

    pkts[recv_cnt] = pkt;
    recv_cnt++;
    pkt_counter_++;

    if (is_timestamp_) {
      // Tag packet: to calculate the global timestamp (in usec) of this packet
      uint64_t tsec = pkthdr_.ts.tv_sec;
      uint64_t tusec = pkthdr_.ts.tv_usec;
      uint64_t ts = ((tsec - init_tsec_) * 1000000 + tusec - init_tusec_);
      tag_packet(pkt, offset_, ts);
    }
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
