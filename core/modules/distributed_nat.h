#ifndef BESS_MODULES_DISTRIBUTED_NAT_H_
#define BESS_MODULES_DISTRIBUTED_NAT_H_

#include <hiredis/hiredis.h>
#include <set>
#include <string>
#include <tuple>
#include <map>

#include "nat.h"
#include "../module.h"
#include "../utils/cuckoo_map.h"
#include "../utils/endian.h"
#include "../utils/ip.h"
#include "../utils/mcslock.h"
#include "../utils/random.h"

// Theory of NAT operation:
//
// Definitions:
// Endpoint = <IPv4 address, port>
// Forward direction = outbound (internal -> external)
// Reverse direction = inbound (external -> internal)
//
// There is a single hash table of Endpoint -> (Endpoint, timestamp), which
// contains both forward and reverse mapping. They have the same lifespan.
// (e.g., if one entry is deleted, its peer is also deleted)
//
// Suppose the table is empty, and we see a packet A:a ===> B:b.
// Then we find a free external endpoint A':a' for the internal endpoint A:a
// from the pool and create two entries:
// - entry 1  A:a -> A':a'
// - entry 2  A':a' -> A:a
// Then the packet is updated to A':a' ===> B:b (with entry 1).
// When a return packet B:b ===> A':a' comes in, the destination (since it is
// reverse dir) endpoint is B:b ===> A:a (with entry 2).

using bess::utils::be32_t;
using bess::utils::be16_t;
using bess::utils::Ipv4Prefix;

class DistributedNAT final: public Module {
public:
  struct Address {
    const be32_t ip;
    const be16_t port;
    Address(be32_t ip, be16_t port): ip(ip), port(port) {}
    bool operator<(const Address& addr) const {
      return ip.value() < addr.ip.value();
    }
  };

  struct Entry {
    be32_t ip;
    be16_t port;
    bool active;
    bool owned; // whether the rule is created by this NAT
    // bool ack; // TODO: current flow completed

    Entry(be32_t ip, be16_t port, bool active, bool owned): ip(ip), port(port), active(active), owned(owned) {}
  };

  static const Commands cmds;

  // Set up the Redis client context. Set up |ext_addrs| and |port_ranges|.
  CommandResponse Init(const bess::pb::DistributedNATArg &arg);
  CommandResponse GetInitialArg(const bess::pb::EmptyArg &);

  CommandResponse CommandAddInternalIP(const bess::pb::DistributedNATCommandAddInternalIPArg &);
  CommandResponse CommandGetAllRules(const bess::pb::EmptyArg &);
  CommandResponse CommandClearAllRules(const bess::pb::EmptyArg &);

  void ProcessBatch(Context *ctx, bess::PacketBatch *batch) override;

  bool IsInternalTraffic(be32_t sip) const;

  // Returns the number of active NAT entries (flows)
  std::string GetDesc() const override;

private:
  using HashTable = bess::utils::CuckooMap<Endpoint, NatEntry, Endpoint::Hash,
                                           Endpoint::EqualTo>;

  // 5 minutes for entry expiration (rfc4787 REQ-5-c)
  const uint64_t kTimeOutNs = 300ull * 1000 * 1000 * 1000;

  // how many times shall we try to find a free port number?
  static const int kMaxTrials = 128;

  HashTable::Entry *CreateNewEntry(const Endpoint &internal, uint64_t now);

  // This function inserts a new flow to the redis store.
  void UploadRule(const Endpoint &endpoint, const NatEntry &entry);

  void RemoveRule(const Endpoint& endpoint);

  bool FetchRule(const Endpoint& endpoint, NatEntry &entry);

  // This function fetches all flows from the redis store to local cache.
  void rules_sync_global();
  void rules_reset_global();

  std::string redis_service_ip_;

  // The reusable connection context to a redis server.
  redisContext *redis_ctx_;

  // Reusable reply pointer.
  redisReply* redis_reply_;

  be32_t ip_;

  std::map<Address, Entry> rules_;
  std::string kRedisKey_ = "NAT";

  uint64_t last_refresh_;  // in nanoseconds (ctx.current_ns)

  // A set of internal hosts. This is to determine whether a flow
  // is originated from an internal host. Note: NAT should NOT
  // process a new flow originated from an external host.
  std::vector<Ipv4Prefix> int_addrs_;

  std::vector<be32_t> ext_addrs_;  

  // Port ranges available for each address. The first index is the same as the
  // ext_addrs_ range.
  std::vector<std::vector<PortRange>> port_ranges_;

  HashTable map_;
  Random rng_;

  mcslock lock_;
};

#endif  // BESS_MODULES_DISTRIBUTED_NAT_H_
