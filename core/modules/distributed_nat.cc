#include "distributed_nat.h"

#include <algorithm>
#include <numeric>

#include "../utils/endian.h"
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
using IpProto = bess::utils::Ipv4::Proto;
using bess::utils::Udp;
using bess::utils::Tcp;
using bess::utils::Icmp;
using bess::utils::ChecksumIncrement16;
using bess::utils::ChecksumIncrement32;
using bess::utils::UpdateChecksumWithIncrement;
using bess::utils::UpdateChecksum16;
using bess::utils::be32_t;
using bess::utils::be16_t;
using bess::utils::Ipv4Prefix;

namespace {
const std::string kDefaultDistributedNATRedisDB = "2";
const int kDefaultDistributedNATRedisPort = 6379;

enum Direction {
  kForward = 0,  // internal -> external
  kReverse = 1,  // external -> internal
  kInvalid = 2,
};

// Given a |ip| header and a |l4| header, returns a parsed EndPoint.
inline std::pair<bool, Endpoint> ExtractEndpoint(const Ipv4 *ip,
                                                const void *l4,
                                                Direction dir) {
  IpProto proto = static_cast<IpProto>(ip->protocol);

  if (likely(proto == IpProto::kTcp || proto == IpProto::kUdp)) {
    // UDP and TCP share the same layout for port numbers
    const Udp *udp = static_cast<const Udp *>(l4);
    Endpoint ret;

    if (dir == kForward) {
      ret = {.addr = ip->src, .port = udp->src_port, .protocol = proto};
    } else {
      ret = {.addr = ip->dst, .port = udp->dst_port, .protocol = proto};
    }

    return std::make_pair(true, ret);
  }

  // slow path
  if (proto == IpProto::kIcmp) {
    const Icmp *icmp = static_cast<const Icmp *>(l4);
    Endpoint ret;

    if (icmp->type == 0 || icmp->type == 8 || icmp->type == 13 ||
        icmp->type == 15 || icmp->type == 16) {
      if (dir == kForward) {
        ret = {
            .addr = ip->src, .port = icmp->ident, .protocol = IpProto::kIcmp};
      } else {
        ret = {
            .addr = ip->dst, .port = icmp->ident, .protocol = IpProto::kIcmp};
      }

      return std::make_pair(true, ret);
    }
  }

  return std::make_pair(
      false, Endpoint{.addr = ip->src, .port = be16_t(0), .protocol = 0});
}

template <Direction dir>
inline void Stamp(Ipv4 *ip, void *l4, const Endpoint &before,
                  const Endpoint &after) {
  IpProto proto = static_cast<IpProto>(ip->protocol);
  DCHECK_EQ(before.protocol, after.protocol);
  DCHECK_EQ(before.protocol, proto);

  if (dir == kForward) {
    ip->src = after.addr;
  } else {
    ip->dst = after.addr;
  }

  uint32_t l3_increment =
      ChecksumIncrement32(before.addr.raw_value(), after.addr.raw_value());
  ip->checksum = UpdateChecksumWithIncrement(ip->checksum, l3_increment);

  uint32_t l4_increment =
      l3_increment +
      ChecksumIncrement16(before.port.raw_value(), after.port.raw_value());

  if (likely(proto == IpProto::kTcp || proto == IpProto::kUdp)) {
    Udp *udp = static_cast<Udp *>(l4);
    if (dir == kForward) {
      udp->src_port = after.port;
    } else {
      udp->dst_port = after.port;
    }

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
  } else {
    DCHECK_EQ(proto, IpProto::kIcmp);
    Icmp *icmp = static_cast<Icmp *>(l4);
    icmp->ident = after.port;

    // ICMP does not have a pseudo header
    icmp->checksum = UpdateChecksum16(icmp->checksum, before.port.raw_value(),
                                      after.port.raw_value());
  }
}
} // namespace

const Commands DistributedNAT::cmds = {
  {"add_internal_ip", "DistributedNATCommandAddInternalIPArg",
   MODULE_CMD_FUNC(&DistributedNAT::CommandAddInternalIP), Command::THREAD_UNSAFE},
  {"get_rules", "EmptyArg",
   MODULE_CMD_FUNC(&DistributedNAT::CommandGetAllRules), Command::THREAD_SAFE},
  {"clear_rules", "EmptyArg",
   MODULE_CMD_FUNC(&DistributedNAT::CommandClearAllRules), Command::THREAD_SAFE},
};

CommandResponse DistributedNAT::Init(const bess::pb::DistributedNATArg &arg) {
  // Check before committing any changes.
  for (const auto &address_range : arg.ext_addrs()) {
    for (const auto &range : address_range.port_ranges()) {
      if (range.begin() >= range.end() || range.begin() > UINT16_MAX ||
          range.end() > UINT16_MAX) {
        return CommandFailure(EINVAL, "Port range for address %s is malformed",
                              address_range.ext_addr().c_str());
      }
    }
  }

  for (const auto &address_range : arg.ext_addrs()) {
    auto ext_addr = address_range.ext_addr();
    be32_t addr;

    bool ret = bess::utils::ParseIpv4Address(ext_addr, &addr);
    if (!ret) {
      return CommandFailure(EINVAL, "invalid IP address %s", ext_addr.c_str());
    }

    ext_addrs_.push_back(addr);
    // Add a port range list
    std::vector<PortRange> port_list;
    if (address_range.port_ranges().size() == 0) {
      port_list.emplace_back(PortRange{
          .begin = 0u, .end = 65535u, .suspended = false,
      });
    }
    for (const auto &range : address_range.port_ranges()) {
      port_list.emplace_back(PortRange{
          .begin = (uint16_t)range.begin(),
          .end = (uint16_t)range.end(),
          // Control plane gets to decide if the port range can be used.
          .suspended = range.suspended()});
    }
    port_ranges_.push_back(port_list);
  }

  if (ext_addrs_.empty()) {
    return CommandFailure(EINVAL,
                          "at least one external IP address must be specified");
  }

  // Sort so that GetInitialArg is predictable and consistent.
  std::sort(ext_addrs_.begin(), ext_addrs_.end());

  if (arg.redis_service_ip().empty()) {
    LOG(INFO) << "No Redis service IP provided.";
    redis_service_ip_ = "";
  } else {
    redis_service_ip_ = arg.redis_service_ip();

    // Connecting
    struct timeval timeout = {5, 500000}; // 5.5 seconds
    int redis_port = kDefaultDistributedNATRedisPort;
    if (arg.redis_port() > 0) {
      redis_port = int(arg.redis_port());
    }
    redis_ctx_ = (redisContext*)redisConnectWithTimeout(
                  redis_service_ip_.c_str(), redis_port, timeout);

    if (redis_ctx_ == nullptr) {
      CommandFailure(EINVAL, "Error: failed to allocate a Redis context");
    } else if (redis_ctx_->err) {
      return CommandFailure(EINVAL, "Connection error: %s", redis_ctx_->errstr);
    } else {
      // Succeed.
      if (!arg.redis_password().empty()) {
        redis_reply_ = (redisReply*)redisCommand(redis_ctx_, "AUTH %s", arg.redis_password().c_str());
        if (redis_reply_->type == REDIS_REPLY_ERROR) {
          freeReplyObject(redis_reply_);
          redis_ctx_ = nullptr;
          return CommandFailure(EINVAL, "Auth error: failed to auth with Redis");
        }
      }
    }
  }

  std::string select = "SELECT ";
  if (arg.redis_db() > 0) {
    select += std::to_string(int(arg.redis_db()));
  } else {
    select += kDefaultDistributedNATRedisDB;
  }
  redis_reply_ = (redisReply *)redisCommand(redis_ctx_, select.c_str());
  freeReplyObject(redis_reply_);

  last_refresh_ = 0;

  mcs_lock_init(&lock_);

  return CommandSuccess();
}

CommandResponse DistributedNAT::GetInitialArg(const bess::pb::EmptyArg &) {
  bess::pb::NATArg resp;
  for (size_t i = 0; i < ext_addrs_.size(); i++) {
    auto ext = resp.add_ext_addrs();
    ext->set_ext_addr(ToIpv4Address(ext_addrs_[i]));
    for (auto irange : port_ranges_[i]) {
      auto erange = ext->add_port_ranges();
      erange->set_begin((uint32_t)irange.begin);
      erange->set_end((uint32_t)irange.end);
      erange->set_suspended(irange.suspended);
    }
  }
  return CommandSuccess(resp);
}

CommandResponse DistributedNAT::CommandAddInternalIP(
    const bess::pb::DistributedNATCommandAddInternalIPArg & arg) {
  for (const auto& ip : arg.internal_ips()) {
    int_addrs_.push_back(Ipv4Prefix(ip));
  }
  return CommandSuccess();
}

CommandResponse DistributedNAT::CommandGetAllRules(const bess::pb::EmptyArg &) {
  rules_sync_global();

  bess::pb::DistributedNATCommandGetAllRulesResponse response;
  for (auto it = rules_.begin(); it != rules_.end(); ++it) {
    auto r = response.add_rules();
    r->set_internal_ip(ToIpv4Address(it->first.ip));
    r->set_internal_port(it->first.port.value());
    r->set_external_ip(ToIpv4Address(it->second.ip));
    r->set_external_port(it->second.port.value());
  }
  response.set_timestamp(std::to_string(last_refresh_));
  return CommandSuccess(response);
}

CommandResponse DistributedNAT::CommandClearAllRules(const bess::pb::EmptyArg &) {
  rules_reset_global();

  map_.Clear();
  return CommandSuccess();
}

// Not necessary to inline this function, since it is less frequently called
DistributedNAT::HashTable::Entry *DistributedNAT::CreateNewEntry(
                                    const Endpoint &src_internal,
                                    uint64_t now) {
  NatEntry forward_entry;
  NatEntry reverse_entry;
  Endpoint src_external;

  // First, fetch remote states.
  bool is_remote_found = FetchRule(src_internal, forward_entry);

  if (is_remote_found) {
    // |forward_entry| is filled with the previous entry.
    src_external = forward_entry.endpoint;
    reverse_entry.endpoint = src_internal;
    map_.Insert(src_external, reverse_entry);

    return map_.Insert(src_internal, forward_entry);
  }

  // An internal IP address is always mapped to the same external IP address,
  // in an deterministic manner (rfc4787 REQ-2)
  size_t hashed = rte_hash_crc(&src_internal.addr, sizeof(be32_t), 0);
  size_t ext_addr_index = hashed % ext_addrs_.size();
  src_external.addr = ext_addrs_[ext_addr_index];
  src_external.protocol = src_internal.protocol;

  for (const auto &port_range : port_ranges_[ext_addr_index]) {
    uint16_t min;
    uint16_t range;  // consider [min, min + range) port range
    // Avoid allocation from an unusable range. We do this even when a range is
    // already in use since we might want to reclaim it once flows die out.
    if (port_range.suspended) {
      continue;
    }

    if (src_internal.protocol == IpProto::kIcmp) {
      min = port_range.begin;
      range = port_range.end - port_range.begin;
    } else {
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
    }

    // Start from a random port, then do linear probing
    uint16_t start_port = min + rng_.GetRange(range);
    uint16_t port = start_port;
    int trials = 0;

    do {
      src_external.port = be16_t(port);
      auto *hash_reverse = map_.Find(src_external);
      if (hash_reverse == nullptr) {
      found:
        // Found an available src_internal <-> src_external mapping
        reverse_entry.endpoint = src_internal;
        map_.Insert(src_external, reverse_entry);

        forward_entry.endpoint = src_external;

        //Update the global state.
        // UploadRule(src_external, reverse_entry);
        UploadRule(src_internal, forward_entry);

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

          // Update the global state
          RemoveRule(hash_forward->first);
          // RemoveRule(hash_reverse->first);

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

void DistributedNAT::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  uint64_t now = ctx->current_ns;

  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    // Determine the flow's direction.
    Direction dir = kInvalid;
    if (IsInternalTraffic(ip->src)) {
      dir = kForward;
    } else if (IsInternalTraffic(ip->dst)) {
      dir = kReverse;
    } else {
      DropPacket(ctx, pkt);
      continue;
    }

    size_t ip_bytes = (ip->header_length) << 2;
    void *l4 = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);

    bool valid_protocol;
    Endpoint before;
    std::tie(valid_protocol, before) = ExtractEndpoint(ip, l4, dir);

    if (!valid_protocol) {
      DropPacket(ctx, pkt);
      continue;
    }

    // |before| is the internal (physical) EndPoint.
    auto *hash_item = map_.Find(before);
    if (hash_item == nullptr) {
      if (dir != kForward || !(hash_item = CreateNewEntry(before, now))) {
        DropPacket(ctx, pkt);
        continue;
      }
    }

    // only refresh for outbound packets, rfc4787 REQ-6
    if (dir == kForward) {
      hash_item->second.last_refresh = now;
    }

    if (dir == kForward)
      Stamp<kForward>(ip, l4, before, hash_item->second.endpoint);
    else
      Stamp<kReverse>(ip, l4, before, hash_item->second.endpoint);
    EmitPacket(ctx, pkt, 0);
  }
}

inline bool DistributedNAT::IsInternalTraffic(be32_t sip) const {
  for (const auto& internal_ip : int_addrs_) {
    if (internal_ip.Match(sip)) {
      return true;
    }
  }
  return false;
}

void DistributedNAT::UploadRule(const Endpoint &endpoint, const NatEntry &entry) {
  // push on global storage
  std::string field ("");
  field += ToIpv4Address(endpoint.addr) + ":" +
           std::to_string(endpoint.port.value());

  std::string value ("");
  value += ToIpv4Address(entry.endpoint.addr) + ":" +
           std::to_string(entry.endpoint.port.value());

  redis_reply_ = (redisReply *)redisCommand(redis_ctx_, "HSET %s %s %s", kRedisKey_.c_str(), field.c_str(), value.c_str());
  if (redis_reply_ == nullptr) {
    LOG(ERROR) << "Error: bad redis connection";
    return;
  } else if (redis_reply_->type == REDIS_REPLY_ERROR) {
    LOG(ERROR) << "Error: bad redis request";
  }

  freeReplyObject(redis_reply_);
}

void DistributedNAT::RemoveRule(const Endpoint& endpoint) {
  std::string field ("");
  field += ToIpv4Address(endpoint.addr) + ":" +
           std::to_string(endpoint.port.value());

  redis_reply_ = (redisReply *)redisCommand(redis_ctx_, "HDEL %s %s %s", kRedisKey_.c_str(), field.c_str());
  freeReplyObject(redis_reply_);
}

bool DistributedNAT::FetchRule(const Endpoint& endpoint, NatEntry &entry) {
  std::string value;
  std::string field ("");
  field += ToIpv4Address(endpoint.addr) + ":" +
           std::to_string(endpoint.port.value());

  redis_reply_ = (redisReply *)redisCommand(redis_ctx_, "HGET %s %s", kRedisKey_.c_str(), field.c_str());
  if (redis_reply_ == nullptr) {
    LOG(ERROR) << "Error: bad redis connection";
    return false;
  } else if (redis_reply_->type == REDIS_REPLY_ERROR) {
    LOG(ERROR) << "Error: bad redis request";
  } else {
    value = redis_reply_->str;
    size_t m = value.find(':');
    ParseIpv4Address(value.substr(0, m), &entry.endpoint.addr);
    entry.endpoint.port = be16_t(std::stoi(value.substr(m + 1, value.length() - m - 1)));

    freeReplyObject(redis_reply_);
    redis_reply_ = nullptr;
    return true;
  }

  freeReplyObject(redis_reply_);
  redis_reply_ = nullptr;
  return false;
}

void DistributedNAT::rules_sync_global() {
  std::string key;
  std::string value;
  be32_t dst_ip, src_ip;
  be16_t dst_port, src_port;

  redis_reply_ = (redisReply *)redisCommand(redis_ctx_,"HGETALL %s", kRedisKey_);
  for (unsigned i = 0; i < redis_reply_->elements; i++) {
    if ((i&1) == 0) {
      key = redis_reply_->element[i]->str;
    } else {
      value = redis_reply_->element[i]->str;

      size_t m = key.find(':');
      ParseIpv4Address(key.substr(0, m), &dst_ip);
      dst_port = be16_t(std::stoi(key.substr(m + 1, key.length() - m - 1)));

      m = value.find(':');
      ParseIpv4Address(value.substr(0, m), &src_ip);
      src_port = be16_t(std::stoi(key.substr(m + 1, key.length() - m - 1)));

      rules_.insert(std::make_pair(Address(dst_ip, dst_port), Entry(src_ip, src_port, true, false)));
    }
  }
  freeReplyObject(redis_reply_);
}

void DistributedNAT::rules_reset_global() {
  std::string key;
  redisReply* tmp_reply = nullptr;

  redis_reply_ = (redisReply *)redisCommand(redis_ctx_,"HGETALL %s", kRedisKey_);
  for (unsigned i = 0; i < redis_reply_->elements; i++) {
    if ((i&1) == 0) {
      key = redis_reply_->element[i]->str;

      tmp_reply = (redisReply *)redisCommand(redis_ctx_,"HDEL %s %s", kRedisKey_, key);
      if (tmp_reply != nullptr) {
        freeReplyObject(tmp_reply);
        tmp_reply = nullptr;
      }
    }
  }
  freeReplyObject(redis_reply_);
  redis_reply_ = nullptr;
}

std::string DistributedNAT::GetDesc() const {
  // Divide by 2 since the table has both forward and reverse entries
  return bess::utils::Format("%zu entries", map_.Count() / 2);
}

ADD_MODULE(DistributedNAT, "DistributedNAT",
          "Dynamic Network address/port translator in a distributed way")
