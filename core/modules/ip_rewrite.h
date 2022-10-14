#ifndef BESS_MODULES_IP_REWRITE_H_
#define BESS_MODULES_IP_REWRITE_H_

#include "../module.h"
#include "utils/ether.h"
#include "utils/ip.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::be32_t;

// Swap source and destination IP addresses and UDP/TCP ports
class IPRewrite final : public Module {
 public:
  IPRewrite() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const bess::pb::IPRewriteArg &arg);
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

 private:
  Ethernet::Address ether_dst_;
  be32_t ip_dst_;
};

#endif  // BESS_MODULES_IP_REWRITE_H_
