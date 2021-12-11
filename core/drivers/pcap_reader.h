#ifndef BESS_DRIVERS_PCAP_READER_H_
#define BESS_DRIVERS_PCAP_READER_H_

#include <pcap.h>
#include <glog/logging.h>

#include "../utils/ether.h"
#include "../utils/ip.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::be16_t;
using bess::utils::be32_t;

class PCAPReader final : public Port {
 public:
  static const int MAX_TEMPLATE_SIZE = 1514;

  CommandResponse Init(const bess::pb::PCAPReaderArg &arg);

  void DeInit() override;
  // PCAP has no notion of queue so unlike parent (port.cc) quid is ignored.
  int SendPackets(queue_t qid, bess::Packet **pkts, int cnt) override;
  // Ditto above: quid is ignored.
  int RecvPackets(queue_t qid, bess::Packet **pkts, int cnt) override;

 private:
  unsigned char tmpl_[MAX_TEMPLATE_SIZE] = {};

  bool is_timestamp_ = false;
  bool is_reset_payload_ = false;
  size_t offset_;
  // The module's packet counter
  uint64_t pkt_counter_ = 0;
  // If true, then the Ethernet header has been removed for all packets
  bool is_eth_missing_ = false;
  // The Ethernet header template for packets without an Ethernet header
  Ethernet eth_template_;
  // The module's temporal packet pointer and pcap header
  const uint8_t *pkt_ = nullptr;
  // The module's pcap file handler
  pcap_t *pcap_handle_ = nullptr;
  // Initial time origin
  uint64_t init_tsec_;
  uint64_t init_tusec_;
};

#endif // BESS_DRIVERS_PCAP_READER_H_
