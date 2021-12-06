#include "replayer.h"

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/time.h"
#include "../utils/udp.h"

namespace {
const int kDefaultTagOffset = 64;

void GetTimestamp(bess::Packet *pkt, size_t offset, uint64_t *time) {
  *time = *(pkt->head_data<uint64_t *>(offset));
}
}

CommandResponse Replayer::Init(const bess::pb::ReplayerArg &arg) {
  if (arg.offset()) {
    offset_ = arg.offset();
  } else {
    offset_ = kDefaultTagOffset;
  }
  return CommandSuccess();
}

void Replayer::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  // uint64_t now_us = tsc_to_us(rdtsc());
  // Read the timestamp in the TCP header.
  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    uint64_t pkt_time = 0;
    GetTimestamp(batch->pkts()[i], offset_, &pkt_time);
    if (pkt_time) {
checktime:
      if (tsc_to_us(rdtsc()) > pkt_time) {
        EmitPacket(ctx, batch->pkts()[i], 0);
      } else {
        goto checktime;
      }
    }
  }
}

ADD_MODULE(Replayer, "replayer",
           "Replay a pcap packet trace that keeps the original traffic dynamics")
