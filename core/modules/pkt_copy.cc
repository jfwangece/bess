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

#include "pkt_copy.h"

#include "../utils/checksum.h"
#include "../utils/ether.h"
#include "../utils/ip.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;

void PktCopy::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();

  uint64_t start = rdtsc();

  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    if (is_first_pkt) {
      std::cout << "pkt length = " << pkt->total_len();
      is_first_pkt = false;
    }

    new_pkts_[i] = bess::Packet::copy(pkt);
    rte_prefetch0(new_pkts_[i]);

    Ethernet *eth = new_pkts_[i]->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);

    if (ip->ttl > 1) {
      // N to N-1 and 2 to 1 are identical for checksum purpose
      // We use constant numbers here for efficiency.
      //ip->checksum = bess::utils::UpdateChecksum16(ip->checksum, 2, 1);
      //ip->ttl -= 1;
      EmitPacket(ctx, new_pkts_[i]);
    } else {
      DropPacket(ctx, new_pkts_[i]);
    }
  }

  bess::Packet::Free(batch->pkts(), cnt);

  if (cnt > 30) {
    per_round_pkt_cnts_.push_back(int(rdtsc() - start) / cnt);
    if (per_round_pkt_cnts_.size() == 10000) {
      std::sort(per_round_pkt_cnts_.begin(), per_round_pkt_cnts_.end());
      LOG(INFO) << "p50 = " << per_round_pkt_cnts_[5000] << ", p99 = " << per_round_pkt_cnts_[9900];
      per_round_pkt_cnts_.clear();
    }
  }
}

ADD_MODULE(PktCopy, "PacketCopy", "Microbenchmark on copying packets")
