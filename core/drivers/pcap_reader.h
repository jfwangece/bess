#ifndef BESS_DRIVERS_PCAP_READER_H_
#define BESS_DRIVERS_PCAP_READER_H_

#include <pcap.h>
#include <glog/logging.h>

class PCAPReader final : public Port {
 public:
  CommandResponse Init(const bess::pb::PCAPReaderArg &arg);

  void DeInit() override;
  // PCAP has no notion of queue so unlike parent (port.cc) quid is ignored.
  int SendPackets(queue_t qid, bess::Packet **pkts, int cnt) override;
  // Ditto above: quid is ignored.
  int RecvPackets(queue_t qid, bess::Packet **pkts, int cnt) override;

 private:
  bool is_timestamp_ = false;
  // The module's packet counter
  uint64_t pkt_counter_ = 0;
  // The module's temporal packet pointer and pcap header
  const uint8_t *pkt_ = nullptr;
  // The module's pcap file handler
  pcap_t *pcap_handle_ = nullptr;
};

#endif // BESS_DRIVERS_PCAP_READER_H_
