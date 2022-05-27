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

#include "invisv_udp_proxy.h"

#include <algorithm>
#include <numeric>
#include <string>

#include "../utils/checksum.h"
#include "../utils/common.h"
#include "../utils/ether.h"
#include "../utils/format.h"
#include "../utils/icmp.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/udp.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Udp;
using bess::utils::Tcp;
using bess::utils::Icmp;
using bess::utils::ChecksumIncrement16;
using bess::utils::ChecksumIncrement32;
using bess::utils::UpdateChecksumWithIncrement;
using bess::utils::UpdateChecksum16;

const Commands INVISVUDPProxy::cmds = {
    {"get_initial_arg", "EmptyArg",
     MODULE_CMD_FUNC(&INVISVUDPProxy::GetInitialArg), Command::THREAD_SAFE},
    {"get_runtime_config", "EmptyArg",
     MODULE_CMD_FUNC(&INVISVUDPProxy::GetRuntimeConfig), Command::THREAD_SAFE},
    {"set_runtime_config", "EmptyArg",
     MODULE_CMD_FUNC(&INVISVUDPProxy::SetRuntimeConfig), Command::THREAD_SAFE},
    {"set_proxy", "INVISVUDPProxySetProxyEndpointArg",
     MODULE_CMD_FUNC(&INVISVUDPProxy::SetUDPProxy), Command::THREAD_SAFE},
    {"set_next_hop_proxy", "INVISVUDPProxySetProxyEndpointArg",
     MODULE_CMD_FUNC(&INVISVUDPProxy::SetNextHopUDPProxy),
     Command::THREAD_SAFE},
    {"get_proxy", "EmptyArg", MODULE_CMD_FUNC(&INVISVUDPProxy::GetUDPProxy),
     Command::THREAD_SAFE},
    {"get_next_hop_proxy", "EmptyArg",
     MODULE_CMD_FUNC(&INVISVUDPProxy::GetNextHopUDPProxy),
     Command::THREAD_SAFE},
    {"set_client", "INVISVUDPProxySetClientEndpointArg",
     MODULE_CMD_FUNC(&INVISVUDPProxy::SetUDPProxyClient),
     Command::THREAD_SAFE},
};

namespace {
static inline std::tuple<bool, Endpoint, Endpoint> ExtractEndpoint(
                                              const Ipv4 *ip, const void *l4) {
  IpProto proto = static_cast<IpProto>(ip->protocol);

  if (likely(proto == IpProto::kUdp)) {
    // UDP and TCP share the same layout for port numbers
    const Udp *udp = static_cast<const Udp *>(l4);
    Endpoint src = {.addr = ip->src, .port = udp->src_port, .protocol = proto};
    Endpoint dst = {.addr = ip->dst, .port = udp->dst_port, .protocol = proto};

    return std::make_tuple(true, src, dst);
  }

  return std::make_tuple(false,
      Endpoint{.addr = ip->src, .port = be16_t(0), .protocol = 0},
      Endpoint{.addr = ip->dst, .port = be16_t(0), .protocol = 0});
}

inline void Stamp(Ipv4 *ip, void *l4,
                  const Endpoint &old_src, const Endpoint &old_dst,
                  const Endpoint &new_src, const Endpoint &new_dst) {
  IpProto proto = static_cast<IpProto>(ip->protocol);
  DCHECK_EQ(old_src.protocol, new_src.protocol);
  DCHECK_EQ(old_src.protocol, proto);

  ip->src = new_src.addr;
  ip->dst = new_dst.addr;

  uint32_t l3_increment =
    ChecksumIncrement32(old_src.addr.raw_value(), new_src.addr.raw_value()) +
    ChecksumIncrement32(old_dst.addr.raw_value(), new_dst.addr.raw_value());
  ip->checksum = UpdateChecksumWithIncrement(ip->checksum, l3_increment);

  uint32_t l4_increment = l3_increment +
    ChecksumIncrement16(old_src.port.raw_value(), new_src.port.raw_value()) +
    ChecksumIncrement16(old_dst.port.raw_value(), new_dst.port.raw_value());

  Udp *udp = static_cast<Udp *>(l4);
  udp->src_port = new_src.port;
  udp->dst_port = new_dst.port;

  if (proto == IpProto::kTcp) {
    Tcp *tcp = static_cast<Tcp *>(l4);
    tcp->checksum = UpdateChecksumWithIncrement(tcp->checksum, l4_increment);
  } else {
    // NOTE: UDP checksum is tricky in two ways:
    // 1. if the old checksum field was 0 (not set), no need to update
    // 2. if the updated value is 0, use 0xffff (rfc768)
    if (udp->checksum != 0) {
      udp->checksum =
          UpdateChecksumWithIncrement(udp->checksum, l4_increment) ?: 0xffff;
    }
  }
}
} // namespace

// TODO(torek): move this to set/get runtime config
CommandResponse INVISVUDPProxy::Init(const bess::pb::INVISVUDPProxyArg &arg) {
  // Check before committing any changes.
  uint32_t num_port_ranges = arg.udp_port_ranges().size();
  for (uint32_t i = 0; i < num_port_ranges; i++) {
    auto &range = arg.udp_port_ranges().Get(i);
    if (range.begin() >= range.end() || range.begin() > UINT16_MAX ||
        range.end() > UINT16_MAX) {
      return CommandFailure(EINVAL, "Port range %d is malformed", i);
    }
  }

  // Add a port range list
  for (const auto &range : arg.udp_port_ranges()) {
    udp_port_ranges_.emplace_back(PortRange{
        .begin = (uint16_t)range.begin(),
        .end = (uint16_t)range.end(),
        // Control plane gets to decide if the port range can be used.
        .suspended = range.suspended()});
  }
  if (udp_port_ranges_.size() == 0) {
    udp_port_ranges_.emplace_back(PortRange{
        .begin = 0u, .end = 65535u, .suspended = false,
    });
  }

  if (arg.proxy_addr().size() > 0) {
    be32_t addr;
    bool ret = bess::utils::ParseIpv4Address(arg.proxy_addr(), &addr);
    if (!ret) {
      return CommandFailure(EINVAL,
          "invalid proxy IP address %s", arg.proxy_addr().c_str());
    }
    curr_udp_proxy_.addr = addr;
    curr_udp_proxy_.port = be16_t(arg.proxy_port());
    curr_udp_proxy_.protocol = IpProto::kUdp;
  } else {
    curr_udp_proxy_.addr = be32_t(0);
    curr_udp_proxy_.port = be16_t(0);
    curr_udp_proxy_.protocol = IpProto::kUdp;
  }

  if (arg.next_hop_proxy_addr().size() > 0) {
    be32_t addr;
    bool ret = bess::utils::ParseIpv4Address(arg.next_hop_proxy_addr(), &addr);
    if (!ret) {
      return CommandFailure(EINVAL,
          "invalid proxy IP address %s", arg.next_hop_proxy_addr().c_str());
    }
    next_hop_udp_proxy_.addr = addr;
    next_hop_udp_proxy_.port = be16_t(arg.proxy_port());
    next_hop_udp_proxy_.protocol = IpProto::kUdp;
  } else {
    next_hop_udp_proxy_.addr = be32_t(0);
    next_hop_udp_proxy_.port = be16_t(0);
    next_hop_udp_proxy_.protocol = IpProto::kUdp;
  }

  return CommandSuccess();
}

CommandResponse INVISVUDPProxy::GetInitialArg(const bess::pb::EmptyArg &) {
  bess::pb::INVISVUDPProxyArg resp;
  for (const auto &range : udp_port_ranges_) {
    auto erange = resp.add_udp_port_ranges();
    erange->set_begin((uint32_t)range.begin);
    erange->set_end((uint32_t)range.end);
    erange->set_suspended(range.suspended);
  }
  resp.set_proxy_addr(ToIpv4Address(curr_udp_proxy_.addr));
  resp.set_proxy_port(curr_udp_proxy_.port.value());
  resp.set_next_hop_proxy_addr(ToIpv4Address(next_hop_udp_proxy_.addr));
  resp.set_next_hop_proxy_port(next_hop_udp_proxy_.port.value());
  return CommandSuccess(resp);
}

CommandResponse INVISVUDPProxy::GetRuntimeConfig(const bess::pb::EmptyArg &) {
  return CommandSuccess();
}

CommandResponse INVISVUDPProxy::SetRuntimeConfig(const bess::pb::EmptyArg &) {
  return CommandSuccess();
}

CommandResponse INVISVUDPProxy::SetUDPProxy(
      const bess::pb::INVISVUDPProxySetProxyEndpointArg &arg) {
  if (arg.proxy_addr().size() > 0) {
    be32_t addr;
    bool ret = bess::utils::ParseIpv4Address(arg.proxy_addr(), &addr);
    if (!ret) {
      return CommandFailure(EINVAL,
          "invalid proxy IP address %s", arg.proxy_addr().c_str());
    }
    curr_udp_proxy_.addr = addr;
    curr_udp_proxy_.port = be16_t(arg.proxy_port());
    curr_udp_proxy_.protocol = IpProto::kUdp;
    return CommandSuccess();
  }
  return CommandFailure(EINVAL, "Incorrect proxy endpoint");
}

CommandResponse INVISVUDPProxy::SetNextHopUDPProxy(
      const bess::pb::INVISVUDPProxySetProxyEndpointArg &arg) {
  if (arg.proxy_addr().size() > 0) {
    be32_t addr;
    bool ret = bess::utils::ParseIpv4Address(arg.proxy_addr(), &addr);
    if (!ret) {
      return CommandFailure(EINVAL,
          "invalid next-hop proxy IP address %s", arg.proxy_addr().c_str());
    }
    next_hop_udp_proxy_.addr = addr;
    next_hop_udp_proxy_.port = be16_t(arg.proxy_port());
    next_hop_udp_proxy_.protocol = IpProto::kUdp;
    return CommandSuccess();
  }
  return CommandFailure(EINVAL, "Incorrect next-hop proxy endpoint");
}

CommandResponse INVISVUDPProxy::GetUDPProxy(const bess::pb::EmptyArg &) {
  bess::pb::INVISVUDPProxyGetProxyEndpointArg r;
  r.set_proxy_addr(ToIpv4Address(curr_udp_proxy_.addr));
  r.set_proxy_port(curr_udp_proxy_.port.value());
  return CommandSuccess(r);
}

CommandResponse INVISVUDPProxy::GetNextHopUDPProxy(const bess::pb::EmptyArg &) {
  bess::pb::INVISVUDPProxyGetProxyEndpointArg r;
  r.set_proxy_addr(ToIpv4Address(next_hop_udp_proxy_.addr));
  r.set_proxy_port(next_hop_udp_proxy_.port.value());
  return CommandSuccess(r);
}

CommandResponse INVISVUDPProxy::SetUDPProxyClient(
              const bess::pb::INVISVUDPProxySetClientEndpointArg &arg) {
  if (arg.client_addr().size() > 0) {
    be32_t addr;
    bool ret = bess::utils::ParseIpv4Address(arg.client_addr(), &addr);
    if (!ret) {
      return CommandFailure(EINVAL,
          "invalid client IP address %s", arg.client_addr().c_str());
    }

    Endpoint client;
    client.addr = addr;
    client.port = be16_t(arg.client_port());
    client.protocol = IpProto::kUdp;

    std::lock_guard<std::mutex> guard(client_lock_);
    auto client_it = udp_proxy_clients_.find(client.addr);
    if (client_it != udp_proxy_clients_.end()) {
      client_it->second = arg.allow();
    } else { // new
      udp_proxy_clients_.emplace(std::piecewise_construct,
          std::make_tuple(client.addr), std::make_tuple(arg.allow()));
    }

    return CommandSuccess();
  }
  return CommandFailure(EINVAL, "Incorrect client endpoint");
}

// Not necessary to inline this function, since it is less frequently called
INVISVUDPProxy::HashTable::Entry *INVISVUDPProxy::CreateNewEntry(
                                           const Endpoint &src_internal,
                                           uint64_t now) {
  Endpoint src_external;

  // This UDP proxy sends packets as if they were sent by the client.
  // Each client endpoint is mapped to the current UDP proxy's IP and
  // an un-used UDP port.
  src_external.addr = curr_udp_proxy_.addr;
  src_external.protocol = src_internal.protocol;

  // |port_ranges_| must have at least one element.
  for (const auto &port_range : udp_port_ranges_) {
    uint16_t min;
    uint16_t range;  // consider [min, min + range) port range
    // Avoid allocation from an unusable range. We do this even when a range is
    // already in use since we might want to reclaim it once flows die out.
    if (port_range.suspended) {
      continue;
    }

    if (src_internal.port == be16_t(0)) {
      // ignore port number 0
      return nullptr;
    } else if (src_internal.port & ~be16_t(1023)) {
      if (port_range.end <= 1024u) {
        continue;
      }
      min = std::max((uint16_t)1024, port_range.begin);
      range = port_range.end - min + 1;
    } else {
      // Privileged ports are mapped to privileged ports (rfc4787 REQ-5-a)
      if (port_range.begin >= 1023u) {
        continue;
      }
      min = port_range.begin;
      range = std::min((uint16_t)1023, port_range.end) - min;
    }

    // Start from a random port, then do linear probing
    uint16_t start_port = min + rng_.GetRange(range);
    uint16_t port = start_port;
    int trials = 0;

    std::lock_guard<std::mutex> guard(map_lock_);
    do {
      src_external.port = be16_t(port);
      auto *hash_reverse = map_.Find(src_external);
      if (src_external.port != curr_udp_proxy_.port &&
          hash_reverse == nullptr) {
      found:
        // Found an available src_internal <-> src_external mapping
        NatEntry forward_entry;
        NatEntry reverse_entry;

        reverse_entry.endpoint = src_internal;
        map_.Insert(src_external, reverse_entry);

        forward_entry.endpoint = src_external;
        return map_.Insert(src_internal, forward_entry);
      } else {
        // A':a' is not free, but it might have been expired.
        // Check with the forward hash entry since timestamp refreshes only for
        // forward direction.
        auto *hash_forward = map_.Find(hash_reverse->second.endpoint);

        // Forward and reverse entries must share the same lifespan.
        DCHECK(hash_forward != nullptr);

        if (now - hash_forward->second.last_refresh > kTimeOutNs) {
          // Found an expired mapping. Remove A':a' <-> A'':a''...
          map_.Remove(hash_forward->first);
          map_.Remove(hash_reverse->first);
          goto found;  // and go install A:a <-> A':a'
        }
      }

      port++;
      trials++;

      // Out of range? Also check if zero due to uint16_t overflow
      if (port == 0 || port >= min + range) {
        port = min;
      }
      // FIXME: Should not try for kMaxTrials.
    } while (port != start_port && trials < kMaxTrials);
  }
  return nullptr;
}

void INVISVUDPProxy::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  uint64_t now = ctx->current_ns;

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    size_t ip_bytes = (ip->header_length) << 2;
    void *l4 = reinterpret_cast<uint8_t *>(ip) + ip_bytes;

    bool valid_protocol;
    Endpoint src, dst;
    std::tie(valid_protocol, src, dst) = ExtractEndpoint(ip, l4);

    if (!valid_protocol) {
      DropPacket(ctx, pkt);
      continue;
    }

    Direction dir = kReverse;
    if (!IsReverseTraffic(src, dst)) {
      if (!IsForwardTraffic(src, dst)) {
        DropPacket(ctx, pkt);
        continue;
      }
      dir = kForward;
    }

    Endpoint hash_key = dir == kForward ? src : dst;
    map_lock_.lock();
    auto *hash_item = map_.Find(hash_key);
    map_lock_.unlock();

    if (hash_item == nullptr) {
      if (dir != kForward || !(hash_item = CreateNewEntry(src, now))) {
        DropPacket(ctx, pkt);
        continue;
      }
    }

    // only refresh for outbound packets, rfc4787 REQ-6
    if (dir == kForward) {
      hash_item->second.last_refresh = now;
      Stamp(ip, l4, src, dst, hash_item->second.endpoint, next_hop_udp_proxy_);
    } else {
      Stamp(ip, l4, src, dst, curr_udp_proxy_, hash_item->second.endpoint);
    }

    EmitPacket(ctx, pkt, ctx->current_igate);
  }
}

bool INVISVUDPProxy::IsForwardTraffic(Endpoint &src, Endpoint &dst) {
  Endpoint::EqualTo eq;
  if (!eq(dst, curr_udp_proxy_)) {
    return false;
  }

  std::lock_guard<std::mutex> guard(client_lock_);
  const auto it = udp_proxy_clients_.find(src.addr);
  if (it == udp_proxy_clients_.end()) { // Unknown client
    return false;
  }
  if (!it->second) { // Deny
    return false;
  }
  return true;
}

bool INVISVUDPProxy::IsReverseTraffic(Endpoint &src, Endpoint &dst) {
  Endpoint::EqualTo eq;
  if (!eq(src, next_hop_udp_proxy_)) { // Not from the next-hop proxy
    return false;
  }
  if (dst.addr != curr_udp_proxy_.addr) { // Not for the current proxy
    return false;
  }
  return true;
}

std::string INVISVUDPProxy::GetDesc() const {
  // Divide by 2 since the table has both forward and reverse entries
  return bess::utils::Format("%zu entries", map_.Count() / 2);
}

ADD_MODULE(INVISVUDPProxy, "udp_proxy",
           "Dynamic network address/port translator for UDP traffic")
