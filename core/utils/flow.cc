#include "flow.h"

namespace bess {
namespace utils {
bool ParseFlowFromPacket(Flow *flow, bess::Packet *pkt) {
  Ethernet *eth = pkt->head_data<Ethernet *>();
  if (eth->ether_type != be16_t(Ethernet::Type::kIpv4)) {
    return false;
  }

  Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
  flow->src_ip = ip->src;
  flow->dst_ip = ip->dst;

  size_t ip_bytes = ip->header_length << 2;
  if (ip->protocol == Ipv4::Proto::kTcp) {
    Tcp *tcp = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
    flow->src_port = tcp->src_port;
    flow->dst_port = tcp->dst_port;
    flow->proto_ip = ip->protocol;
  } else if (ip->protocol == Ipv4::Proto::kUdp) {
    Udp *udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
    flow->src_port = udp->src_port;
    flow->dst_port = udp->dst_port;
    flow->proto_ip = ip->protocol;
  } else {
    flow->src_port = be16_t(0);
    flow->dst_port = be16_t(0);
    flow->proto_ip = 0;
  }
  return true;
}
} // namespace utils
} // namespace bess
