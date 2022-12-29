#include "pcap.h"
#include "pcap_reader.h"

#include <string>

#include "../utils/checksum.h"
#include "../utils/flow.h"
#include "../utils/packet_tag.h"

using bess::utils::Flow;
using bess::utils::TagPacketTimestamp;

// static
int PCAPReader::total_pcaps_ = 0;
std::shared_mutex PCAPReader::mtx_;
bool pcap_block[DEFAULT_PCAPQ_COUNT] = {false};

namespace {
const int kDefaultTagOffset = 64;
struct pcap_pkthdr _pkthdr;
struct Flow _flow;
} // namespace

CommandResponse PCAPReader::Init(const bess::pb::PCAPReaderArg& arg) {
  // whether record the per-packet timestamp in the per-packet metadata.
  is_timestamp_ = false;
  if (arg.timestamp()) {
    is_timestamp_ = true;
  }

  is_reset_payload_ = false;
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
    pkt_ = pcap_next(pcap_handle_, &_pkthdr);
    if (!pkt_) {
      return CommandFailure(EINVAL, "Error reading an empty pcap file.");
    }

    // Note: some PCAP files have Ethernet headers removed
    // Decide whether Ethernet headers were removed or not
    is_eth_missing_ = *(uint16_t*)pkt_ == 0x0045 || *(uint16_t*)pkt_ == 0x0845 || *(uint16_t*)pkt_ == 0x4845 || *(uint16_t*)pkt_ == 0x0a14;

    init_tsec_ = _pkthdr.ts.tv_sec;
    init_tnsec_ = _pkthdr.ts.tv_usec;
  }

  const_payload_size_ = 554;

  // Initialize the local packet queue and batch (128 K slots)
  uint32_t slots = 131072;
  int bytes = llring_bytes_with_slots(slots);
  local_queue_ =
      reinterpret_cast<llring *>(std::aligned_alloc(alignof(llring), bytes));
  if (!local_queue_) {
    return CommandFailure(ENOMEM,
                         "must have enough memory to allocate a packet buffer");
  }
  int ret = llring_init(local_queue_, slots, 1, 1);
  if (ret) {
    std::free(local_queue_);
    return CommandFailure(EINVAL,
                         "must call llring_init for the packet buffer");
  }

  local_batch_ = reinterpret_cast<bess::PacketBatch *>
          (std::aligned_alloc(alignof(bess::PacketBatch), sizeof(bess::PacketBatch)));
  if (!local_batch_) {
    return CommandFailure(ENOMEM,
                         "must have enough memory to allocate a packet batch");
  }
  local_batch_->clear();

  // Initialize payload template
  memset(tmpl_, 1, MAX_TEMPLATE_SIZE);

  // Initialize Ethernet header template
  eth_template_.src_addr = Ethernet::Address("ec:0d:9a:67:ff:68");
  eth_template_.dst_addr = Ethernet::Address("82:a3:ae:74:72:30"); // VF: 5e:00.2
  eth_template_.ether_type = be16_t(Ethernet::Type::kIpv4);

  // Record the startup timestamp in usec
  last_pkt_ts_ = 0;

  // Initialize the multi-core pcap packet counters
  pcap_id_ = 0;

  return CommandSuccess();
}

void PCAPReader::DeInit() {
  bess::Packet *pkt = nullptr;

  pcap_close(pcap_handle_);

  bess::Packet::Free(local_batch_);

  if (local_queue_) {
    while (llring_sc_dequeue(local_queue_, (void **)&pkt) == 0) {
      bess::Packet::Free(pkt);
    }
    std::free(local_queue_);
    local_queue_ = nullptr;
  }
}

bool PCAPReader::ShouldAllocPkts() {
  return !pcap_block[pcap_id_];
}

int PCAPReader::RecvPackets(queue_t, bess::Packet** pkts, int cnt) {
  if (pcap_handle_ == nullptr) { return 0; }

  // Allocate packets
  if (ShouldAllocPkts()) {
    local_batch_->clear();

    int rounds = 0;
    while(rounds < 8 &&
        llring_free_count(local_queue_) > 32) {
      // Try to allocate a packet buffer
      bess::Packet* pkt = current_worker.packet_pool()->Alloc();
      if (!pkt) {
        if (local_batch_->cnt()) {
          llring_sp_enqueue_burst(local_queue_,
              reinterpret_cast<void **>(local_batch_->pkts()), local_batch_->cnt());
        }
        break;
      }

      // Read one packet from the pcap file
      pkt_ = pcap_next(pcap_handle_, &_pkthdr);
      if (!pkt_) {
        bess::Packet::Free(pkt);
        break;
      }
      // |caplen| is the number of bytes that are captured;
      // |totallen| is the original packet's byte count;
      int caplen = _pkthdr.caplen;
      int totallen = _pkthdr.len;
      if (const_payload_size_ >= 100) {
        totallen = const_payload_size_;
      }

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

      // Copy L3 and L4 headers
      copy_len = sizeof(Ipv4) + sizeof(Tcp);
      if (copy_len > caplen) {
        copy_len = caplen;
      }
      if (is_eth_missing_) {
        bess::utils::Copy(p + total_copy_len, pkt_, copy_len, true);
      } else {
        bess::utils::Copy(p + total_copy_len, pkt_ + sizeof(Ethernet), copy_len, true);
      }
      total_copy_len += copy_len;

      // Copy payload if the packet's payload is truncated
      if (is_reset_payload_ &&
          totallen > total_copy_len) {
        copy_len = totallen - total_copy_len;
        bess::utils::Copy(p + total_copy_len, tmpl_, copy_len, true);
        total_copy_len += copy_len;
      }

      // Only generate L4 packets
      if (!bess::utils::ParseFlowFromPacket(&_flow, pkt)) {
        bess::Packet::Free(pkt);
        continue;
      }
      if (const_payload_size_ >= 100) {
        Ethernet *eth = pkt->head_data<Ethernet *>();
        Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
        ip->length = be16_t(const_payload_size_);
      }

      if (is_timestamp_) {
        // Tag packet: to calculate the global timestamp (in nsec)
        long tsec = _pkthdr.ts.tv_sec;
        long tnsec = _pkthdr.ts.tv_usec;
        uint64_t ts = uint64_t(tsec - init_tsec_) * 1000000000;
        if (tnsec > init_tnsec_) {
          ts += uint64_t(tnsec - init_tnsec_);
        } else {
          ts -= uint64_t(init_tnsec_ - tnsec);
        }

        TagPacketTimestamp(pkt, offset_, ts - last_pkt_ts_);
        last_pkt_ts_ = ts;
      }

      local_batch_->add(pkt);
      if (local_batch_->cnt() == 32) {
        llring_sp_enqueue_burst(local_queue_,
            reinterpret_cast<void **>(local_batch_->pkts()), local_batch_->cnt());
        local_batch_->clear();
        rounds += 1;
      }
    }
  }

  // Send packets
  int recv_cnt = llring_sc_dequeue_burst(local_queue_,
                  reinterpret_cast<void **>(pkts), cnt);
  pkt_counter_ += recv_cnt;

  return recv_cnt;
}

int PCAPReader::SendPackets(queue_t, bess::Packet** pkts, int cnt) {
  if (pcap_handle_ == nullptr) {
    CHECK(0);  // raise an error
  }

  // Just release the set of packet buffers.
  bess::Packet::Free(pkts, cnt);
  return 0;
}

ADD_DRIVER(PCAPReader, "pcap_reader",
                       "libpcap packet reader from a pcap file")
