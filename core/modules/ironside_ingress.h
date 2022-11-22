#ifndef BESS_MODULES_IRONSIDE_INGRESS_H_
#define BESS_MODULES_IRONSIDE_INGRESS_H_

#include <map>
#include <vector>

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/flow.h"
#include "../utils/ip.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;
using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Flow;
using bess::utils::FlowHash;

class IronsideIngress final : public Module {
 public:
  IronsideIngress() : Module() { max_allowed_workers_ = Worker::kMaxWorkers; }

  CommandResponse Init(const bess::pb::IronsideIngressArg &arg);
  void DeInit() override;

  void UpdateEndpointLB();
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

 private:
  int rewrite_ = 0;
  be32_t ip_mask_;
  be16_t tcp_port_mask_;

  // Load balancing
  int mode_ = 0;
  int ncore_thresh_;
  uint32_t pkt_rate_thresh_;

  // Workers in the cluster.
  std::vector<Ethernet::Address> macs_;
  std::vector<be32_t> ips_;
  std::vector<uint32_t> pkt_cnts_;

  // Routing
  int endpoint_id_ = 0;
  uint64_t last_endpoint_update_ts_ = 0;

  // Per-flow-aggregate connection table
  std::map<uint64_t, int> flow_cache_;
};

#endif  // BESS_MODULES_IRONSIDE_INGRESS_H_
