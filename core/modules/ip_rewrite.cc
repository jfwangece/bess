#include "ip_rewrite.h"

CommandResponse IPRewrite::Init(const bess::pb::IPRewriteArg &arg) {
  ip_dst_ = be32_t(0x0000);
  if (arg.dst_ip().length() > 0) {
    ParseIpv4Address(arg.dst_ip(), &ip_dst_);
  }
  return CommandSuccess();
}

void IPRewrite::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  using bess::utils::Ethernet;
  using bess::utils::Ipv4;

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];
    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    ip->dst = ip_dst_;
  }
  RunNextModule(ctx, batch);
}

ADD_MODULE(IPRewrite, "iprewrite", "Rewrites destination IP address")
