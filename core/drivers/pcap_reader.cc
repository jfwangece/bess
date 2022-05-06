#include "pcap.h"
#include "pcap_reader.h"

#include <string>

#include "../utils/flow.h"

using bess::utils::Flow;

// static
int PCAPReader::total_pcaps_ = 0;
std::mutex PCAPReader::mtx_;
uint64_t PCAPReader::per_pcap_counters_[4] = {0,0,0,0};
uint64_t PCAPReader::per_pcap_max_cnt_ = 0;
uint64_t PCAPReader::per_pcap_min_cnt_ = 0;

namespace {
const int kDefaultTagOffset = 64;

struct pcap_pkthdr pkthdr_;

struct Flow flow;

inline void TagPacketTimestamp(bess::Packet *pkt, size_t offset,
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
  if (arg.reset_payload()) {
    is_reset_payload_ = true;
  }
  if (arg.offset()) {
    offset_ = arg.offset();
  } else {
    offset_ = kDefaultTagOffset;
  }
  const std::string dev = arg.dev();
  char msg_buf[PCAP_ERRBUF_SIZE];
  pcap_handle_ = pcap_open_offline_with_tstamp_precision(dev.c_str(), PCAP_TSTAMP_PRECISION_NANO, msg_buf);

  is_eth_missing_ = false;
  if (pcap_handle_ == nullptr) {
    return CommandFailure(EINVAL, "Error initializing the pcap handle.");
  } else {
    pkt_ = pcap_next(pcap_handle_, &pkthdr_);
    if (!pkt_) {
      return CommandFailure(EINVAL, "Error reading an empty pcap file.");
    }

    // Note: some PCAP files have Ethernet headers removed
    // Decide whether Ethernet headers were removed or not
    is_eth_missing_ = *(uint16_t*)pkt_ == 0x0045 || *(uint16_t*)pkt_ == 0x0845 || *(uint16_t*)pkt_ == 0x4845 || *(uint16_t*)pkt_ == 0x0a14;

    init_tsec_ = pkthdr_.ts.tv_sec;
    init_tnsec_ = pkthdr_.ts.tv_usec;
  }

  // Initialize payload template
  memset(tmpl_, 1, MAX_TEMPLATE_SIZE);
  // Initialize Ethernet header template
  eth_template_.src_addr = Ethernet::Address("ec:0d:9a:67:ff:68");
  eth_template_.dst_addr = Ethernet::Address("82:a3:ae:74:72:30"); // VF: 5e:00.2
  eth_template_.ether_type = be16_t(Ethernet::Type::kIpv4);

  // Record the startup timestamp in usec
  startup_ts_ = tsc_to_us(rdtsc());

  // Initialize the multi-core pcap packet counters
  const std::lock_guard<std::mutex> lock(mtx_);
  if (pcap_index_ == -1) {
    pcap_index_ = total_pcaps_;
    total_pcaps_ += 1;
  }
  per_pcap_counters_[pcap_index_] = 0;

  return CommandSuccess();
}

void PCAPReader::DeInit() {
  pcap_close(pcap_handle_);
}

bool PCAPReader::ShouldAllocPkts() {
  bool should = true;

  const std::lock_guard<std::mutex> lock(mtx_);
  if (pcap_index_ == 0) {
    per_pcap_max_cnt_ = per_pcap_counters_[0];
    per_pcap_min_cnt_ = per_pcap_counters_[0];
    for (int i = 1; i < total_pcaps_; i++) {
      if (per_pcap_counters_[i] > per_pcap_max_cnt_) {
        per_pcap_max_cnt_ = per_pcap_counters_[i];
      }
      if (per_pcap_counters_[i] < per_pcap_min_cnt_) {
        per_pcap_min_cnt_ = per_pcap_counters_[i];
      }
    }
  }

  if (per_pcap_counters_[pcap_index_] == per_pcap_max_cnt_ &&
      per_pcap_max_cnt_ > per_pcap_min_cnt_ + 10000) {
    should = false;
  }
  return should;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
int PCAPReader::RecvPackets(queue_t qid, bess::Packet** pkts, int cnt) {
  if (pcap_handle_ == nullptr) {
    return 0;
  }
  if (!ShouldAllocPkts()) {
    return 0;
  }

  int recv_cnt = 0;
  while(recv_cnt < cnt) {
    // Try to allocate a packet buffer
    bess::Packet* pkt = current_worker.packet_pool()->Alloc();
    if (!pkt) {
      break;
    }

    // read one packet from the pcap file
    pkt_ = pcap_next(pcap_handle_, &pkthdr_);
    if (!pkt_) {
      bess::Packet::Free(pkt);
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

    // Leave a headroom for prepending data
    char *p = pkt->buffer<char *>() + SNBUF_HEADROOM;
    pkt->set_data_off(SNBUF_HEADROOM);
    pkt->set_total_len(totallen);
    pkt->set_data_len(totallen);

    int total_copy_len = 0;
    int copy_len = 0;

    // Note: for NIC ether scoping, always use a fake Ethernet header
    Ethernet* eth = reinterpret_cast<Ethernet *>(p);
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

    // Copy payload if the packet's payload is truncated
    if (totallen > total_copy_len) {
      copy_len = totallen - total_copy_len;
      bess::utils::Copy(p + total_copy_len, tmpl_, copy_len, true);
      total_copy_len += copy_len;
    }

    // Only generate L4 packets
    if (!bess::utils::ParseFlowFromPacket(&flow, pkt)) {
      bess::Packet::Free(pkt);
      continue;
    }

    pkts[recv_cnt] = pkt;
    recv_cnt++;
    pkt_counter_++;

    if (is_timestamp_) {
      // Tag packet: to calculate the global timestamp (in nsec)
      long tsec = pkthdr_.ts.tv_sec;
      long tnsec = pkthdr_.ts.tv_usec;
      uint64_t ts = uint64_t(tsec - init_tsec_) * 1000000000;
      if (tnsec > init_tnsec_) {
        ts += uint64_t(tnsec - init_tnsec_);
      } else {
        ts -= uint64_t(init_tnsec_ - tnsec);
      }
      TagPacketTimestamp(pkt, offset_, ts);
    }
  }

  mtx_.lock();
  per_pcap_counters_[pcap_index_] += recv_cnt;
  mtx_.unlock();

  return recv_cnt;
}
#pragma GCC diagnostic pop

int PCAPReader::SendPackets(queue_t, bess::Packet** pkts, int cnt) {
  if (pcap_handle_ == nullptr) {
    CHECK(0);  // raise an error
  }
  // Just release the set of packet buffers.
  bess::Packet::Free(pkts, cnt);

  return 0;
}

ADD_DRIVER(PCAPReader, "pcap_reader", "libpcap packet reader from a pcap file")
