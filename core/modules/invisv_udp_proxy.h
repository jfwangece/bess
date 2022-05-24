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

#ifndef BESS_MODULES_INVISV_UDP_PROXY_H_
#define BESS_MODULES_INVISV_UDP_PROXY_H_

#include "../module.h"
#include "../pb/module_msg.pb.h"

#include <rte_config.h>
#include <rte_hash_crc.h>

#include <map>
#include <mutex>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "../utils/cuckoo_map.h"
#include "../utils/endian.h"
#include "../utils/random.h"

// Theory of operation:
//
// Definitions:
// Endpoint = <IPv4 address, port>
// UDP proxy = <proxy ingress IPv4 address, proxy ingress UDP port>
// next-hop UDP proxy = <n-proxy IPv4 address, n-proxy UDP port>
// Forward direction:
// [Endpoint -> UDP proxy] ==> [UDP proxy -> next-hop UDP proxy]
// Reverse direction:
// [next-hop UDP proxy -> UDP proxy] ==> [UDP proxy -> Endpoint]
//
// There is a single hash table of Endpoint -> (Endpoint, timestamp), which
// contains both forward and reverse mapping. They have the same lifespan.
// (e.g., if one entry is deleted, its peer is also deleted)
//
// Note: The UDP proxy always has a next-hop UDP proxy C:c.
// Suppose the table is empty, and we see a packet A:a ===> B:b.
// The UDP proxy represents the endpoint A:a to communicate with C:c.
// To do so, we find a free UDP port b' from the pool and create two entries:
// - entry 1  A:a -> B:b'
// - entry 2  B:b' -> A:a
// Then the packet is updated to [A:a, B:b] ===> [B:b', C:c] (with entry 1).
// When a return packet [C:c, B:b'] comes in, the destination (since it is
// reverse dir) endpoint is [B:b, A:a] (with entry 2).

using bess::utils::be16_t;
using bess::utils::be32_t;

struct alignas(8) Endpoint {
  be32_t addr;

  // TCP/UDP port number or ICMP identifier
  be16_t port;

  // L4 protocol (IPPROTO_*). Note that this is a 1-byte field in the IP header,
  // but we store the value in a 2-byte field so that the struct be 8-byte long
  // without a hole, without needing to initialize it explicitly.
  uint16_t protocol;

  bool operator<(const Endpoint &other) const {
    const Endpoint &me = *this;
    const union {
        Endpoint endpoint;
        uint64_t u64;
    } &left = {.endpoint = me}, &right = {.endpoint = other};

    return left.u64 < right.u64;
  }

  struct Hash {
    std::size_t operator()(const Endpoint &e) const {
#if __x86_64
      return crc32c_sse42_u64(
          (static_cast<uint64_t>(e.addr.raw_value()) << 32) |
              (static_cast<uint64_t>(e.port.raw_value()) << 16) |
              static_cast<uint64_t>(e.protocol),
          0);
#else
      return rte_hash_crc(&e, sizeof(uint64_t), 0);
#endif
    }
  };

  struct EqualTo {
    bool operator()(const Endpoint &lhs, const Endpoint &rhs) const {
      const union {
        Endpoint endpoint;
        uint64_t u64;
      } &left = {.endpoint = lhs}, &right = {.endpoint = rhs};

      return left.u64 == right.u64;
    }
  };
};

static_assert(sizeof(Endpoint) == sizeof(uint64_t), "Incorrect Endpoint");

struct NatEntry {
  Endpoint endpoint;

  // last_refresh is only updated for forward-direction (outbound) packets, as
  // per rfc4787 REQ-6. Reverse entries will have an garbage value.
  // We do lazy reclaim of expired; NAT mapping entry will NOT expire unless it
  // runs out of ports in the pool.
  uint64_t last_refresh;  // in nanoseconds (ctx.current_ns)
};

// Port ranges are used to scale out the NAT.
struct PortRange {
  // Start of port range.
  uint16_t begin;
  // End of port range (exclusive).
  uint16_t end;
  // Is range usable, i.e., can we safely give out ports.
  bool suspended;
};

// NAT module. 2 igates and 2 ogates
// igate/ogate 0: forward dir
// igate/ogate 1: reverse dir
class INVISVUDPProxy final : public Module {
 public:
  enum Direction {
    kForward = 0,  // internal -> external
    kReverse = 1,  // external -> internal
  };

  static const gate_idx_t kNumOGates = Worker::kMaxWorkers;
  static const gate_idx_t kNumIGates = Worker::kMaxWorkers;

  static const Commands cmds;

  INVISVUDPProxy()
      : Module() {
    Endpoint curr_udp_proxy_;
    Endpoint next_hop_udp_proxy_;
    max_allowed_workers_ = Worker::kMaxWorkers;
  }

  CommandResponse Init(const bess::pb::INVISVUDPProxyArg &arg);
  CommandResponse GetInitialArg(const bess::pb::EmptyArg &arg);
  CommandResponse GetRuntimeConfig(const bess::pb::EmptyArg &arg);
  CommandResponse SetRuntimeConfig(const bess::pb::EmptyArg &arg);
  CommandResponse SetUDPProxy(
              const bess::pb::INVISVUDPProxySetProxyEndpointArg &arg);
  CommandResponse SetNextHopUDPProxy(
              const bess::pb::INVISVUDPProxySetProxyEndpointArg &arg);
  CommandResponse GetUDPProxy(const bess::pb::EmptyArg &);
  CommandResponse GetNextHopUDPProxy(const bess::pb::EmptyArg &);
  CommandResponse SetUDPProxyClient(
              const bess::pb::INVISVUDPProxySetClientEndpointArg &arg);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  // returns the number of active NAT entries (flows)
  std::string GetDesc() const override;

 private:
  using HashTable = bess::utils::CuckooMap<Endpoint, NatEntry, Endpoint::Hash,
                                           Endpoint::EqualTo>;

  // 5 minutes for entry expiration (rfc4787 REQ-5-c)
  static const uint64_t kTimeOutNs = 300ull * 1000 * 1000 * 1000;

  // how many times shall we try to find a free port number?
  static const int kMaxTrials = 128;

  HashTable::Entry *CreateNewEntry(const Endpoint &internal, uint64_t now);

  // If |dst| equals to |curr_udp_proxy_| and |src| is allowed: |src|'s value
  // is true in |udp_proxy_clients_|, return true. Otherwise, return false.
  bool IsForwardTraffic(Endpoint &src, Endpoint &dst);

  // If |src| equals to |next_hop_udp_proxy_| and |dst|'s IP matches
  // |curr_udp_proxy_| IP, return true. Otherwise, return false.
  bool IsReverseTraffic(Endpoint &src, Endpoint &dst);

  // |igate| is coupled with the ogate at the same index
  inline gate_idx_t GetOGate(gate_idx_t igate) { return igate; }

  std::vector<be32_t> ext_addrs_;

  Endpoint curr_udp_proxy_;
  Endpoint next_hop_udp_proxy_;

  // Port ranges available for each address. The first index is the same as the
  // ext_addrs_ range.
  std::vector<std::vector<PortRange>> port_ranges_;

  // |map_| contains all [client <-> this proxy <-> next-hop] proxy connections.
  HashTable map_;
  std::mutex map_lock_;

  // |udp_proxy_clients_| contains this UDP proxy's client. For each client, the
  // value indicates whether this proxy forwards its traffic or not.
  std::map<Endpoint, bool> udp_proxy_clients_;
  std::mutex client_lock_;

  Random rng_;
};

#endif  // BESS_MODULES_INVISV_UDP_PROXY_H_
