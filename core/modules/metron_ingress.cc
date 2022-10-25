#include <metron_ingress.h>
#include <metron.h>

namespace metron {

struct llring* nic_q[128];

} // metron

CommandResponse MetronIngress::Init(const bess::pb::MetronIngressArg&) {
  flow_aggregates_.clear();
  mask_to_core_.clear();
  // Initially, all flow aggregates go to core 0.
  flow_aggregates_.emplace_back(FlowAggregate());
  for (uint32_t i = 0; i < 256; i++) {
    mask_to_core_.emplace(i, 0);
  }

  return CommandSuccess();
}

void MetronIngress::DeInit() {
  flow_aggregates_.clear();
  mask_to_core_.clear();
  // Initially, all flow aggregates go to core 0.
  flow_aggregates_.emplace_back(FlowAggregate());
  for (uint32_t i = 0; i < 256; i++) {
    mask_to_core_.emplace(i, 0);
  }
}

void MetronIngress::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  // UpdateEndpointLB();

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    if (ip->protocol != Ipv4::Proto::kTcp) {
      DropPacket(ctx, pkt);
      continue;
    }
    // size_t ip_bytes = ip->header_length << 2;
    uint32_t flow_id = ip->dst.value() & 0xff;
    int core_id = 0;

    pkt_cnts_[flow_id] += 1;

    auto it = mask_to_core_.find(flow_id);
    if (it == mask_to_core_.end()) {
      bool found = false;
      // This is a new flow.
      for (auto& range : flow_aggregates_) {
        if (flow_id >= range.start && flow_id <= range.end) {
          std::tie(it, std::ignore) = mask_to_core_.emplace(
                                  std::piecewise_construct,
                                  std::make_tuple(flow_id), std::make_tuple());
          it->second = range.core;
          found = true;
          break;
        }
      }
      if (!found) {
        LOG(FATAL) << "a flow does not belong to any flow aggregates";
      }
    }

    // Send to core
    core_id = it->second;
    if (core_id < 0) {
      LOG(FATAL) << "invalid core index";
    }

    EmitPacket(ctx, pkt);
  }
}

ADD_MODULE(MetronIngress, "metron",
           "A ToR-layer ingress with a per-flow-aggregate hash table")
