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

#ifndef BESS_MODULES_SnortIDS_H_
#define BESS_MODULES_SnortIDS_H_

#include <rte_config.h>
#include <rte_hash_crc.h>

#include <map>
#include <string>
#include <tuple>
#include <utility>
#include <vector>
#include <queue>

#include "url_filter.h"
#include "../module.h"
#include "../packet.h"
#include "../pb/module_msg.pb.h"
#include "../utils/tcp_flow_reconstruct.h"
#include "../utils/trie.h"

using bess::utils::TcpFlowReconstruct;
using bess::utils::Trie;
using bess::utils::be16_t;
using bess::utils::be32_t;

// A module of HTTP URL filtering. Ends an HTTP connection if the Host field
// matches the blacklist.
// igate/ogate 0: traffic from internal network to external network
// igate/ogate 1: traffic from external network to internal network
class SnortIDS final : public Module {
 public:
  typedef std::pair<std::string, std::string> Url;

  static const Commands cmds;
  static const gate_idx_t kNumIGates = 2;
  static const gate_idx_t kNumOGates = 2;

  CommandResponse Init([[maybe_unused]]const bess::pb::SnortArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

 private:
  std::unordered_map<std::string, Trie<std::tuple<>>> blacklist_;
  std::unordered_map<Flow, FlowRecord, FlowHash> flow_cache_;
};

#endif  // BESS_MODULES_SnortIDS_H_
