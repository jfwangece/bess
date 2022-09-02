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

#include "snort_ids.h"
#include "aho_corasick.h"

#include <algorithm>
#include <tuple>
#include <iostream>

#include "../utils/checksum.h"
#include "../utils/ether.h"
#include "../utils/format.h"
#include "../utils/http_parser.h"
#include "../utils/ip.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;

const uint64_t TIME_OUT_NS = 5ull * 1000 * 1000 * 1000;  // 5 seconds

const Commands SnortIDS::cmds = {
    {"add", "SnortIDSArg", MODULE_CMD_FUNC(&SnortIDS::CommandAdd),
     Command::THREAD_UNSAFE},
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&SnortIDS::CommandClear),
     Command::THREAD_UNSAFE}};

CommandResponse SnortIDS::Init(const bess::pb::SnortIDSArg &arg) {
  keyword_count_ = arg.keywords_size();
  min_keyword_len_ = 100;
  std::vector<std::string> words;
  for (int i = 0; i < keyword_count_; i++) {
    words.push_back(arg.keywords(i));
    min_keyword_len_ = std::min(arg.keywords(i).length(), min_keyword_len_);
  }
  BuildMatchingMachine(words);

  return CommandSuccess();
}

CommandResponse SnortIDS::CommandAdd(const bess::pb::SnortIDSArg &arg) {
  Init(arg);
  return CommandSuccess();
}

CommandResponse SnortIDS::CommandClear(const bess::pb::EmptyArg &) {
  keyword_count_ = 0;
  return CommandSuccess();
}

// Note: IDS does not drop packets. It generates records.
void SnortIDS::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);

    if (ip->protocol != Ipv4::Proto::kTcp) {
      continue;
    }

    int ip_bytes = ip->header_length << 2;
    Tcp *tcp =
        reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);

    Flow flow;
    flow.src_ip = ip->src;
    flow.dst_ip = ip->dst;
    flow.src_port = tcp->src_port;
    flow.dst_port = tcp->dst_port;

    uint64_t now = ctx->current_ns;

    // Find existing flow, if we have one.
    std::unordered_map<Flow, FlowRecord, FlowHash>::iterator it =
        flow_cache_.find(flow);

    /**
     * * Throw out packets from flows that have expired or been analyzed.
     * * When is a flow considered to be analyzed?
     **/
    if (it != flow_cache_.end()) {
      if (now >= it->second.ExpiryTime()) {
        // Discard old flow and start over.
        flow_cache_.erase(it);
        it = flow_cache_.end();
      } else if (it->second.IsAnalyzed()) {
        // This module has finished analyzing this flow. Skip it.
        continue;
      }
    }

    if (it == flow_cache_.end()) {
      // Don't have a flow, or threw an aged one out.  If there's no
      // SYN in this packet the reconstruct code will fail.  This is
      // a common case (for any flow that got analyzed and allowed);
      // skip a pointless emplace/erase pair for such packets.
      if (tcp->flags & Tcp::Flag::kSyn) {
        std::tie(it, std::ignore) = flow_cache_.emplace(
            std::piecewise_construct, std::make_tuple(flow), std::make_tuple());
      } else {
        // Ignore non-SYN packet.
        continue;
      }
    }

    FlowRecord &record = it->second;
    TcpFlowReconstruct &buffer = record.GetBuffer();

    // If the reconstruct code indicates failure, treat this
    // as a flow to pass.  Note: we only get failure if there is
    // something seriously wrong; we get success if there are holes
    // in the data (in which case the contiguous_len() below is short).
    bool success = buffer.InsertPacket(pkt);
    if (!success) {
      flow_cache_.erase(it);
      continue;
    }

    // Update the default flow entry timeout timestamp
    record.pkt_cnt_ += 1;
    record.SetExpiryTime(now + TIME_OUT_NS);

    bool matched = false;
    if (record.pkt_cnt_ > 25 &&
        record.pkt_cnt_ % 25 == 0 &&
        buffer.contiguous_len() >= 5 * min_keyword_len_) {
      const char *buffer_data = buffer.buf();
      std::string payload_str(buffer_data);

      std::vector<int> match_results = SearchWords(keyword_count_, payload_str);
      for (int any_match : match_results) {
        if (any_match > 0) {
          matched = true;
          break;
        }
      }
    }

    if (matched) {
      // Mark the flow and record it.
      it->second.SetAnalyzed();
    }

    // Once FIN is observed, or we've seen all the headers and decided
    // to pass the flow, there is no more need to reconstruct the flow.
    // NOTE: if FIN is lost on its way to destination, this will simply pass
    // the retransmitted packet.
    if (tcp->flags & Tcp::Flag::kFin) {
      flow_cache_.erase(it);
    }
  }

  RunNextModule(ctx, batch);
}

ADD_MODULE(SnortIDS, "snort_ids",
           "Intrusion detection that uses aho_corasick algorithm to match keyword strings")
