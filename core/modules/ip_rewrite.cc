#include "ip_rewrite.h"

CommandResponse IPRewrite::Init(const bess::pb::IPRewriteArg &arg) {
  ether_dst_ = Ethernet::Address("01:23:45:67:89:ab");
  if (arg.dst_eth().length() > 0) {
    ether_dst_ = Ethernet::Address(arg.dst_eth());
  }

  ip_dst_ = be32_t(0x0000);
  if (arg.dst_ip().length() > 0) {
    ParseIpv4Address(arg.dst_ip(), &ip_dst_);
  }
  return CommandSuccess();
}

void IPRewrite::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    eth->dst_addr = ether_dst_;
    ip->dst = ip_dst_;
  }
  RunNextModule(ctx, batch);
}

ADD_MODULE(IPRewrite, "iprewrite", "Rewrites destination IP address")
