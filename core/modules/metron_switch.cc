#include <nfv_ctrl_msg.h>
#include <metron_switch.h>

CommandResponse MetronSwitch::Init(const bess::pb::MetronSwitchArg& arg) {
  worker_id_ = 0;
  if (arg.wid() > 0) {
    worker_id_ = arg.wid();
  }

  num_cores_ = 1;
  if (arg.ncore() > 0) {
    num_cores_ = int(arg.ncore());
  }

  for (int i = 0; i < num_cores_; i++) {
    pkt_batch_[i] = reinterpret_cast<bess::PacketBatch *>
      (std::aligned_alloc(alignof(bess::PacketBatch), sizeof(bess::PacketBatch)));
  }
  return CommandSuccess();
}

void MetronSwitch::DeInit() {
  for (int i = 0; i < num_cores_; i++) {
    if (pkt_batch_[i] != nullptr) {
      bess::Packet::Free(pkt_batch_[i]);
      std::free(pkt_batch_[i]);
      pkt_batch_[i] = nullptr;
    }
  }
  return;
}

void MetronSwitch::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  for (int i = 0; i < num_cores_; i++) {
    pkt_batch_[i]->clear();
  }

  uint32_t dst_core = 0;
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
    dst_core = tcp->reserved; // decode
    pkt_batch_[dst_core]->add(pkt);
  }

  // Enqueue packet batches
  for (int i = 0; i < num_cores_; i++) {
    struct llring* q = bess::ctrl::local_mc_q[i];
    if (pkt_batch_[i]->cnt()) {
      int queued =
          llring_mp_enqueue_burst(q, (void**)pkt_batch_[i]->pkts(), pkt_batch_[i]->cnt());
      if (queued < pkt_batch_[i]->cnt()) {
        int to_drop = pkt_batch_[i]->cnt() - queued;
        bess::Packet::Free(pkt_batch_[i]->pkts() + queued, to_drop);
      }
    }
  }
}

ADD_MODULE(MetronSwitch, "metron",
           "A ToR-layer ingress with a per-flow-aggregate hash table")
