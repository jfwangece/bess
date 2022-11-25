#include <metron_ingress.h>

CommandResponse MetronIngress::Init(const bess::pb::MetronIngressArg& arg) {
  ips_.clear();
  macs_.clear();
  flow_aggregates_.clear();
  flow_to_core_.clear();

  for (const auto &host : arg.endpoints()) {
    macs_.push_back(Ethernet::Address(host.mac()));

    be32_t addr;
    auto host_addr = host.ip();
    bool ret = bess::utils::ParseIpv4Address(host_addr, &addr);
    if (!ret) {
      return CommandFailure(EINVAL, "invalid IP address %s", host_addr.c_str());
    }
    ips_.push_back(addr);
  }

  // Initially, all flow aggregates go to core 0.
  flow_aggregates_.emplace_back(FlowAggregate(0, 255, 0));
  for (uint32_t i = 0; i < 255; i++) {
    flow_to_core_.emplace(i, 0);
    pkt_cnts_[i] = 0;
  }

  return CommandSuccess();
}

void MetronIngress::DeInit() {
  flow_aggregates_.clear();
  flow_to_core_.clear();
  // Initially, all flow aggregates go to core 0.
  flow_aggregates_.emplace_back(FlowAggregate());
  for (uint32_t i = 0; i < 256; i++) {
    flow_to_core_.emplace(i, 0);
  }
}

void MetronIngress::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    Tcp* tcp = reinterpret_cast<Tcp *>(ip + 1);
    if (ip->protocol != Ipv4::Proto::kTcp) {
      DropPacket(ctx, pkt);
      continue;
    }

    // |flow_id|: [0, 255]
    uint32_t flow_id = ip->dst.value() & 0xff;
    pkt_cnts_[flow_id] += 1;

    uint32_t dst_worker = 0;
    uint32_t dst_core = 0;
    auto it = flow_to_core_.find(flow_id);
    if (it != flow_to_core_.end()) {
      dst_core = it->second;
    } else {
      // This is a new flow.
      for (auto it = flow_aggregates_.begin(); it != flow_aggregates_.end(); it++) {
        if (flow_id >= it->start && flow_id < it->end) {
          dst_core = it->core;
          flow_to_core_.emplace(flow_id, dst_core);
          break;
        }
      }
    }

    // Send to core
    eth->dst_addr = macs_[dst_worker];
    // be32_t before = ip->dst;
    be32_t after = ips_[dst_worker];
    ip->dst = after;
    tcp->reserved = dst_core; // encode

    // uint32_t l3_increment =
    //   ChecksumIncrement32(before.raw_value(), after.raw_value());
    // ip->checksum = UpdateChecksumWithIncrement(ip->checksum, l3_increment);
    // uint32_t l4_increment = l3_increment;
    // tcp->checksum = UpdateChecksumWithIncrement(tcp->checksum, l4_increment);
    tcp->checksum = CalculateIpv4TcpChecksum(*ip, *tcp);
    ip->checksum = CalculateIpv4Checksum(*ip);

    EmitPacket(ctx, pkt);
  }
}

ADD_MODULE(MetronIngress, "metron",
           "A ToR-layer ingress with a per-flow-aggregate hash table")
