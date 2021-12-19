#ifndef BESS_UTILS_FLOW_H_
#define BESS_UTILS_FLOW_H_

#include <rte_config.h>
#include <rte_hash_crc.h>

#include "endian.h"
#include "tcp_flow_reconstruct.h"

using bess::utils::be16_t;
using bess::utils::be32_t;

namespace bess {
namespace utils {

// Actions for handling subsequent packets before an OpenFLow rule is installed.
enum FlowAction {
  // Drop
  kDrop = 0,
  // Queue
  kQueue,
  // Forward with the same rule.
  kForward,
};

// A helper class that defines a TCP flow
class alignas(16) Flow {
 public:
  be32_t src_ip;
  be32_t dst_ip;
  be16_t src_port;
  be16_t dst_port;
  uint8_t proto_ip;
  uint8_t padding0;
  uint16_t padding1;

  Flow() : proto_ip(0), padding0(0), padding1(0) {}

  bool operator==(const Flow &other) const {
    return memcmp(this, &other, sizeof(*this)) == 0;
  }
};

static_assert(sizeof(Flow) == 16, "Flow must be 16 bytes.");

// Hash function for std::unordered_map
struct FlowHash {
  std::size_t operator()(const Flow &f) const {
    uint32_t init_val = 0;

#if __x86_64
    const union {
      Flow flow;
      uint64_t u64[2];
    } &bytes = {.flow = f};

    init_val = crc32c_sse42_u64(bytes.u64[0], init_val);
    init_val = crc32c_sse42_u64(bytes.u64[1], init_val);
#else
    init_val = rte_hash_crc(&f, sizeof(Flow), init_val);
#endif

    return init_val;
  }
};

class FlowLpmRule {
 public:
  bool Match(be32_t sip, be32_t dip, uint8_t pip, be16_t sport, be16_t dport) const {
    return src_ip.Match(sip) && dst_ip.Match(dip) &&
       (proto_ip == pip) &&
       (src_port == be16_t(0) || src_port == sport) &&
       (dst_port == be16_t(0) || dst_port == dport);
  }

  void set_action(uint o_port, const std::string& o_mac) {
    egress_port = o_port;
    egress_mac = o_mac;
    encoded_mac.FromString(o_mac);
    encoded_mac.bytes[0] = o_port & 0xff;
  }

  // Match
  Ipv4Prefix src_ip;
  Ipv4Prefix dst_ip;
  uint8_t proto_ip;
  be16_t src_port;
  be16_t dst_port;

  // Action for subsequent packets.
  FlowAction action;
  uint egress_port;
  std::string egress_mac;

  Ethernet::Address encoded_mac;
  uint64_t active_ts = 0;
};

// Used by snort_ids, url_filter
class FlowRecord {
 public:
  FlowRecord() : pkt_cnt_(0), done_analyzing_(false), acl_pass_(false), buffer_(128), expiry_time_(0) {}

  bool IsAnalyzed() { return done_analyzing_; }
  void SetAnalyzed() { done_analyzing_ = true; }
  bool IsACLPass() { return acl_pass_; }
  void SetACLPass() { acl_pass_ = true; }
  be32_t DstIP() { return dst_ip_; }
  void SetDstIP(be32_t dst_ip) { dst_ip_ = dst_ip; }
  TcpFlowReconstruct &GetBuffer() { return buffer_; }
  uint64_t ExpiryTime() { return expiry_time_; }
  void SetExpiryTime(uint64_t time) { expiry_time_ = time; }

  uint64_t pkt_cnt_;
 private:
  bool done_analyzing_;
  bool acl_pass_;
  be32_t dst_ip_;
  TcpFlowReconstruct buffer_;
  uint64_t expiry_time_;
};

class FlowRoutingRule {
 public:
  FlowRoutingRule(uint o_port, const std::string& o_mac)
      : action_(kForward),
        egress_port_(o_port) {
    encoded_mac_.FromString(o_mac);
    encoded_mac_.bytes[0] = o_port & 0xff;
  }

  FlowAction action_;
  uint egress_port_;
  Ethernet::Address encoded_mac_;
};

} // namespace utils
} // namespace bess

#endif // BESS_UTILS_FLOW_H_
