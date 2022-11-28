#include "nfv_ctrl_msg.h"
#include "metron_ingress.h"
#include "metron_switch.h"

#include "../utils/packet_tag.h"

CommandResponse MetronSwitch::Init(const bess::pb::MetronSwitchArg& arg) {
  worker_id_ = 0;
  if (arg.wid() > 0) {
    worker_id_ = arg.wid();
  }

  num_cores_ = 1;
  if (arg.ncore() > 0) {
    num_cores_ = int(arg.ncore());
    bess::ctrl::ncore = num_cores_;
  }

  for (int i = 0; i < num_cores_; i++) {
    pkt_batch_[i] = reinterpret_cast<bess::PacketBatch *>
      (std::aligned_alloc(alignof(bess::PacketBatch), sizeof(bess::PacketBatch)));
  }

  LOG(INFO) << "total normal cores " << bess::ctrl::ncore;

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

  uint8_t dst_core = 0;
  int cnt = batch->cnt();

  // Tag each packet a current timestamp
  uint64_t now = tsc_to_ns(rdtsc());
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    Tcp* tcp = reinterpret_cast<Tcp *>(ip + 1);
    if (ip->protocol != Ipv4::Proto::kTcp) {
      DropPacket(ctx, pkt);
      continue;
    }

    bess::utils::TagUint64(pkt, WorkerDelayTsTagOffset, now);
    dst_core = tcp->reserved % MaxPerWorkerCoreCount; // decode
    pkt_batch_[dst_core]->add(pkt);
  }

  // Enqueue packet batches
  for (uint8_t i = 0; i < num_cores_; i++) {
    if (pkt_batch_[i]->cnt()) {
      struct llring* q = bess::ctrl::local_mc_q[i];
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
