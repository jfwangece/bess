#ifndef BESS_MODULES_METRON_SWITCH_H_
#define BESS_MODULES_METRON_SWITCH_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "../utils/checksum.h"
#include "../utils/flow.h"
#include "../utils/ip.h"
#include "../utils/lock_less_queue.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;
using bess::utils::be16_t;
using bess::utils::be32_t;
using bess::utils::Flow;
using bess::utils::FlowHash;

class MetronSwitch final : public Module {
 public:
  MetronSwitch() : Module() {
    max_allowed_workers_ = Worker::kMaxWorkers;
  }

  CommandResponse Init(const bess::pb::MetronSwitchArg& arg);
  void DeInit() override;
  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

 private:
  uint32_t worker_id_;
  int num_cores_;

  bess::PacketBatch* pkt_batch_[20] = {nullptr};
};

#endif  // BESS_MODULES_METRON_SWITCH_H_
