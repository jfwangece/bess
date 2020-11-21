#include "mem_checker.h"

#include "timestamp.h"

const Commands MemChecker::cmds = {
  {"get_summary", "EmptyArg",
   MODULE_CMD_FUNC(&MemChecker::CommandGetSummary), Command::THREAD_SAFE},
};

namespace {
int log_invalid_pkts = 0;
int log_valid_pkts = 0;

static bool get_tag(bess::Packet *pkt, size_t offset, uint64_t *time) {
  auto *marker = pkt->head_data<Timestamp::MarkerType *>(offset);

  if (*marker == Timestamp::kMarker) {
    *time = *reinterpret_cast<uint64_t *>(marker + 1);
    return true;
  }
  return false;
}
} // namespace

CommandResponse MemChecker::Init(const bess::pb::MemCheckerArg &arg) {
  if (arg.offset1() > 0) {
    offset1_ = arg.offset1();
  }
  if (arg.offset2() > 0) {
    offset2_ = arg.offset2();
  }

  mcs_lock_init(&lock_);

  return CommandSuccess();
}

void MemChecker::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  
  mcslock_node_t mynode;
  mcs_lock(&lock_, &mynode);

  for (int i = 0; i < cnt; ++i) {
    ++total_packets_cnt_;

    uint64_t start_time1 = 0;
    uint64_t end_time1 = 0;
    uint64_t start_time2 = 0;
    uint64_t end_time2 = 0;

    get_tag(batch->pkts()[i], offset1_, &start_time1);
    get_tag(batch->pkts()[i], offset1_ + 12, &end_time1);
    get_tag(batch->pkts()[i], offset2_, &start_time2);
    get_tag(batch->pkts()[i], offset2_ + 12, &end_time2);

    //LOG(INFO) << start_time1 << ", " << end_time1 << ", " << start_time2 << ", " << end_time2;

    if (start_time2 >= end_time1 || end_time2 <= start_time1) {
      if (log_valid_pkts < 1) {
        LOG(INFO) << "valid: " << start_time1 << ", " << end_time1 << ", " << start_time2 << ", " << end_time2;
        ++log_valid_pkts;
      }
      continue;
    }
    else {
      if (log_invalid_pkts < 1) {
        LOG(INFO) << "invalid: " << start_time1 << ", " << end_time1 << ", " << start_time2 << ", " << end_time2;
        ++log_invalid_pkts;
      }
      ++invalid_packts_cnt_;
    }
  }
  mcs_unlock(&lock_, &mynode);

  RunNextModule(ctx, batch);
}

CommandResponse MemChecker::CommandGetSummary(
    const bess::pb::EmptyArg &) {
  bess::pb::MemCheckerCommandGetSummaryResponse r;

  mcslock_node_t mynode;
  mcs_lock(&lock_, &mynode);

  double ratio = 0;
  if (total_packets_cnt_ > 0)
    ratio = invalid_packts_cnt_ * 100 / total_packets_cnt_;

  r.set_total_packets(total_packets_cnt_);
  r.set_invalid_packets(invalid_packts_cnt_);
  r.set_invalid_ratio(ratio);

  mcs_unlock(&lock_, &mynode);

  return CommandSuccess(r);
}

ADD_MODULE(MemChecker, "mem_checker",
    "Check for invalid memory isolations")
