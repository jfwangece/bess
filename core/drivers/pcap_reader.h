#ifndef BESS_DRIVERS_PCAP_READER_H_
#define BESS_DRIVERS_PCAP_READER_H_

#include <pcap.h>
#include <glog/logging.h>
#include <mutex>
#include <shared_mutex>

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/lock_less_queue.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::be16_t;
using bess::utils::be32_t;

#define DEFAULT_PCAPQ_COUNT 8
extern bool pcap_block[DEFAULT_PCAPQ_COUNT];

class PCAPReader final : public Port {
 public:
  static const int MAX_TEMPLATE_SIZE = 1500;
  static int total_pcaps_;
  static std::shared_mutex mtx_;

  CommandResponse Init(const bess::pb::PCAPReaderArg &arg);
  void DeInit() override;

  // For multi-core pcap replayers, ensure that their packet rates are roughly the same
  bool ShouldAllocPkts();
  // PCAP has no notion of queue so unlike parent (port.cc) quid is ignored.
  int SendPackets(queue_t qid, bess::Packet **pkts, int cnt) override;
  // Ditto above: quid is ignored.
  int RecvPackets(queue_t qid, bess::Packet **pkts, int cnt) override;

 private:
  unsigned char tmpl_[MAX_TEMPLATE_SIZE] = {};

  // The index of this PcapReplay module.
  int pcap_id_ = 0;

  bool is_timestamp_ = false;
  bool is_reset_payload_ = false;

  // Software queue that holds packets
  struct llring* local_queue_;
  bess::PacketBatch* local_batch_;

  // Timestamp offset
  size_t offset_;
  // The module's packet counter
  uint64_t pkt_counter_ = 0;

  // If true, then the Ethernet header has been removed for all packets
  bool is_eth_missing_ = false;
  // The Ethernet header template for packets without an Ethernet header
  Ethernet eth_template_;

  // If |const_payload_size_| >= 100, then this module generates a fixed-size packet
  // (total of |const_payload_size_| bytes)
  int const_payload_size_;

  // The module's temporal packet pointer and pcap header
  const uint8_t *pkt_ = nullptr;
  // The module's pcap file handler
  pcap_t *pcap_handle_ = nullptr;

  // Initial time origin
  long init_tsec_;
  long init_tnsec_;
  uint64_t last_pkt_ts_;
};

#endif // BESS_DRIVERS_PCAP_READER_H_
