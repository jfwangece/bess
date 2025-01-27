// Copyright (c) 2014-2016, The Regents of the University of California.
// Copyright (c) 2016-2017, Nefeli Networks, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the names of the copyright holders nor the names of their
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include "nfv_ctrl_msg.h"
#include "measure.h"
#include "timestamp.h"

#include <iterator>

#include "../utils/common.h"
#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/time.h"
#include "../utils/udp.h"
#include "../utils/sys_measure.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Udp;
using bess::utils::Tcp;
using bess::utils::GetUint32;
using bess::utils::add_debug_tag_nfvcore;

static bool IsTimestamped(bess::Packet *pkt, size_t offset, uint64_t *time) {
  auto *marker = pkt->head_data<Timestamp::MarkerType *>(offset);

  if (*marker == Timestamp::kMarker) {
    *time = *reinterpret_cast<uint64_t *>(marker + 1);
    return true;
  }
  return false;
}

static bool IsQueuestamped(bess::Packet *pkt, size_t offset, uint64_t *qlen) {
  auto *marker = pkt->head_data<Timestamp::MarkerType *>(offset);

  if (*marker == Timestamp::kMarker) {
    *qlen = *reinterpret_cast<uint64_t *>(marker + 1);
    return true;
  }
  return false;
}

const Commands Measure::cmds = {
    {"get_summary", "MeasureCommandGetSummaryArg",
     MODULE_CMD_FUNC(&Measure::CommandGetSummary), Command::THREAD_SAFE},
    {"get_queue", "MeasureCommandGetSummaryArg",
     MODULE_CMD_FUNC(&Measure::CommandGetQueueSummary), Command::THREAD_SAFE},
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&Measure::CommandClear),
     Command::THREAD_SAFE},
};

void Measure::QuadrantPauseUpdates() {
  rte_atomic16_inc(&lb_core_pausing_updates_);
}
void Measure::QuadrantUnpauseUpdates() {
  rte_atomic16_dec(&lb_core_pausing_updates_);
}

void Measure::IsCoreInfo(bess::Packet *pkt) {
  if (bess::ctrl::exp_id != 4 ||
      rte_atomic16_read(&lb_core_pausing_updates_) > 0) {
    return;
  }

  Ethernet *eth = pkt->head_data<Ethernet *>();
  Ipv4* ip = reinterpret_cast<Ipv4 *>(eth + 1);
  Tcp* tcp = reinterpret_cast<Tcp *>(ip + 1);
  uint32_t core_id = tcp->reserved;

  uint64_t max_delay = 0;
  bess::utils::GetUint64(pkt, WorkerDelayTsTagOffset, &max_delay);
  if (bess::ctrl::pc_max_batch_delay[core_id] < max_delay) {
    bess::ctrl::pc_max_batch_delay[core_id] = max_delay;
  }
}

CommandResponse Measure::Init(const bess::pb::MeasureArg &arg) {
  uint64_t latency_ns_max = arg.latency_ns_max();
  uint64_t latency_ns_resolution = arg.latency_ns_resolution();
  if (latency_ns_max == 0) {
    latency_ns_max = kDefaultMaxNs;
  }
  if (latency_ns_resolution == 0) {
    latency_ns_resolution = kDefaultNsPerBucket;
  }
  uint64_t quotient = latency_ns_max / latency_ns_resolution;
  if ((latency_ns_max % latency_ns_resolution) != 0) {
    quotient += 1;  // absorb any remainder
  }
  if (quotient > rtt_hist_.max_num_buckets() / 2) {
    return CommandFailure(E2BIG,
                          "excessive latency_ns_max / latency_ns_resolution");
  }

  size_t num_buckets = quotient;
  rtt_hist_.Resize(num_buckets, latency_ns_resolution);
  jitter_hist_.Resize(num_buckets, latency_ns_resolution);
  queue_hist_.Resize(1024, 1);

  if (arg.offset()) {
    offset_ = arg.offset();
  } else {
    std::string attr_name = "timestamp";
    if (arg.attr_name() != "")
      attr_name = arg.attr_name();

    using AccessMode = bess::metadata::Attribute::AccessMode;
    attr_id_ = AddMetadataAttr(attr_name, sizeof(uint64_t), AccessMode::kRead);
  }

  if (arg.jitter_sample_prob()) {
    jitter_sample_prob_ = arg.jitter_sample_prob();
  } else {
    jitter_sample_prob_ = kDefaultIpDvSampleProb;
  }

  bg_dst_filter_ = false;
  if (arg.bg_dst_filter()) {
    bg_dst_filter_ = true;
  }

  rte_atomic16_set(&lb_core_pausing_updates_, 0);

  bess::ctrl::sys_measure = this;

  mcs_lock_init(&lock_);

  return CommandSuccess();
}

void Measure::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  // We don't use ctx->current_ns here for better accuracy
  uint64_t now_ns = tsc_to_ns(rdtsc());
  size_t offset = offset_;

  mcslock_node_t mynode;
  mcs_lock(&lock_, &mynode);

  pkt_cnt_ += batch->cnt();

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    IsCoreInfo(batch->pkts()[i]);

    uint64_t pkt_time = 0;
    uint64_t qlen = 0;
    if (attr_id_ != -1) {
      pkt_time = get_attr<uint64_t>(this, attr_id_, batch->pkts()[i]);
    }

    if (pkt_time ||
        IsTimestamped(batch->pkts()[i], offset, &pkt_time)) {
      uint64_t diff;

      if (now_ns >= pkt_time) {
        diff = now_ns - pkt_time;
        if (bess::ctrl::exp_id == 0 && diff >= 20000000) { continue; }
        if (add_debug_tag_nfvcore) {
          if (diff >= 2000000) {
            PerPacketTag val;
            GetUint32(batch->pkts()[i], 90, &val.rcore_idle_epoch_count);
            GetUint32(batch->pkts()[i], 94, &val.sw_q_id);
            GetUint32(batch->pkts()[i], 98, &val.sw_q_len);
            stats_.push_back(val);
          }
        }
      } else {
        // The magic number matched, but timestamp doesn't seem correct
        continue;
      }

      bytes_cnt_ += batch->pkts()[i]->total_len();

      rtt_hist_.Insert(diff);
      if (rand_.GetRealNonzero() <= jitter_sample_prob_) {
        if (unlikely(!last_rtt_ns_)) {
          last_rtt_ns_ = diff;
          continue;
        }
        uint64_t jitter = absdiff(diff, last_rtt_ns_);
        jitter_hist_.Insert(jitter);
        last_rtt_ns_ = diff;
      }
    }

    if (IsQueuestamped(batch->pkts()[i], 72, &qlen)) {
      queue_hist_.Insert(qlen);
    }
  }

  mcs_unlock(&lock_, &mynode);

  RunNextModule(ctx, batch);
}

template <typename T>
static void SetHistogram(
    bess::pb::MeasureCommandGetSummaryResponse::Histogram *r, const T &hist,
    uint64_t bucket_width) {
  r->set_count(hist.count);
  r->set_above_range(hist.above_range);
  r->set_resolution_ns(bucket_width);
  r->set_min_ns(hist.min);
  r->set_max_ns(hist.max);
  r->set_avg_ns(hist.avg);
  r->set_total_ns(hist.total);
  for (const auto &val : hist.percentile_values) {
    r->add_percentile_values_ns(val);
  }
}

void Measure::Clear() {
  // vector initialization is expensive thus should be out of critical section
  decltype(rtt_hist_) new_rtt_hist(rtt_hist_.num_buckets(),
                                   rtt_hist_.bucket_width());
  decltype(jitter_hist_) new_jitter_hist(jitter_hist_.num_buckets(),
                                         jitter_hist_.bucket_width());

  // Use move semantics to minimize critical section
  mcslock_node_t mynode;
  mcs_lock(&lock_, &mynode);
  pkt_cnt_ = 0;
  bytes_cnt_ = 0;
  rtt_hist_ = std::move(new_rtt_hist);
  jitter_hist_ = std::move(new_jitter_hist);
  mcs_unlock(&lock_, &mynode);
}

static bool IsValidPercentiles(const std::vector<double> &percentiles) {
  if (percentiles.empty()) {
    return true;
  }

  return std::is_sorted(percentiles.cbegin(), percentiles.cend()) &&
         *std::min_element(percentiles.cbegin(), percentiles.cend()) >= 0.0 &&
         *std::max_element(percentiles.cbegin(), percentiles.cend()) <= 100.0;
}

CommandResponse Measure::CommandGetSummary(
    const bess::pb::MeasureCommandGetSummaryArg &arg) {
  bess::pb::MeasureCommandGetSummaryResponse r;

  std::vector<double> latency_percentiles;
  std::vector<double> jitter_percentiles;

  std::copy(arg.latency_percentiles().begin(), arg.latency_percentiles().end(),
            back_inserter(latency_percentiles));
  std::copy(arg.jitter_percentiles().begin(), arg.jitter_percentiles().end(),
            back_inserter(jitter_percentiles));

  if (!IsValidPercentiles(latency_percentiles)) {
    return CommandFailure(EINVAL, "invalid 'latency_percentiles'");
  }

  if (!IsValidPercentiles(jitter_percentiles)) {
    return CommandFailure(EINVAL, "invalid 'jitter_percentiles'");
  }

  r.set_timestamp(get_epoch_time());
  r.set_packets(pkt_cnt_);
  r.set_bits((bytes_cnt_ + pkt_cnt_ * 24) * 8);
  const auto &rtt = rtt_hist_.Summarize(latency_percentiles);
  const auto &jitter = jitter_hist_.Summarize(jitter_percentiles);

  SetHistogram(r.mutable_latency(), rtt, rtt_hist_.bucket_width());
  SetHistogram(r.mutable_jitter(), jitter, jitter_hist_.bucket_width());

  if (arg.clear()) {
    // Note that some samples might be lost due to the small gap between
    // Summarize() and the next mcs_lock... but we posit that smaller
    // critical section is more important.
    Clear();
  }

  return CommandSuccess(r);
}

CommandResponse Measure::CommandGetQueueSummary(
    const bess::pb::MeasureCommandGetSummaryArg &arg) {
  bess::pb::MeasureCommandGetSummaryResponse r;

  std::vector<double> latency_percentiles;

  std::copy(arg.latency_percentiles().begin(), arg.latency_percentiles().end(),
            back_inserter(latency_percentiles));

  if (!IsValidPercentiles(latency_percentiles)) {
    return CommandFailure(EINVAL, "invalid 'latency_percentiles'");
  }

  r.set_timestamp(get_epoch_time());
  r.set_packets(pkt_cnt_);
  r.set_bits((bytes_cnt_ + pkt_cnt_ * 24) * 8);
  const auto &rtt = queue_hist_.Summarize(latency_percentiles);

  SetHistogram(r.mutable_latency(), rtt, queue_hist_.bucket_width());

  if (arg.clear()) {
    // Note that some samples might be lost due to the small gap between
    // Summarize() and the next mcs_lock... but we posit that smaller
    // critical section is more important.
    Clear();
  }

  return CommandSuccess(r);
}

CommandResponse Measure::CommandClear(const bess::pb::EmptyArg &) {
  if (stats_.size()) {
    bess::utils::LogPacketTags(stats_);
  }
  Clear();
  return CommandResponse();
}

ADD_MODULE(Measure, "measure",
           "measures packet latency (paired with Timestamp module)")
