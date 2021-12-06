#include "distributed_flowcounter.h"

#include <unistd.h>

#include "../utils/endian.h"
#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/udp.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;
using bess::utils::Udp;
using bess::utils::be32_t;

static const std::string kDefaultDistributedFlowCounterDB = "1";
static const int kDefaultRedisServicePort = 6379;

const Commands DistributedFlowCounter::cmds = {
  {"reset", "EmptyArg", MODULE_CMD_FUNC(&DistributedFlowCounter::CommandReset),
   Command::THREAD_SAFE},
  {"clear", "EmptyArg", MODULE_CMD_FUNC(&DistributedFlowCounter::CommandClear),
   Command::THREAD_SAFE},
  {"start", "EmptyArg", MODULE_CMD_FUNC(&DistributedFlowCounter::CommandStart),
   Command::THREAD_SAFE},
  {"stop", "EmptyArg", MODULE_CMD_FUNC(&DistributedFlowCounter::CommandStop),
   Command::THREAD_SAFE},
  {"get_summary", "EmptyArg",
   MODULE_CMD_FUNC(&DistributedFlowCounter::CommandGetSummary), Command::THREAD_SAFE},
};

CommandResponse DistributedFlowCounter::Init(
    const bess::pb::DistributedFlowCounterArg &arg) {
  if (arg.redis_service_ip().empty()) {
    LOG(INFO) << "No Redis service IP provided.";
    redis_service_ip_ = "";
  } else {
    redis_service_ip_ = arg.redis_service_ip();

    // Connecting
    struct timeval timeout = {5, 500000}; // 5.5 seconds
    int redis_port = kDefaultRedisServicePort;
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
    select += kDefaultDistributedFlowCounterDB;
  }
  redis_reply_ = (redisReply *)redisCommand(redis_ctx_, select.c_str());
  freeReplyObject(redis_reply_);

  flow_cache_.clear();
  is_active_ = false;

  mcs_lock_init(&lock_);

  return CommandSuccess();
}

void DistributedFlowCounter::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  if (redis_ctx_ == nullptr || !is_active_) {
    RunNextModule(ctx, batch);
    return;
  }

  uint64_t now = rdtsc();
  int cnt = batch->cnt();
  be16_t sport, dport;
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    size_t ip_bytes = ip->header_length << 2;
    if (ip->protocol == Ipv4::Proto::kTcp) {
      Tcp *tcp = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
      sport = tcp->src_port;
      dport = tcp->dst_port;
    } else if (ip->protocol == Ipv4::Proto::kUdp) {
      Udp *udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
      sport = udp->src_port;
      dport = udp->dst_port;
    } else {
      continue;
    }

    std::string key ("FC:");
    std::string field ("timestamp");

    auto curr_flow = std::make_tuple(ip->src, ip->dst, ip->protocol, sport, dport);
    bool found = flow_cache_.find(curr_flow) != flow_cache_.end();
    if (found) { // No need to update.
      continue;
    } else {
      flow_cache_.insert(curr_flow);

      key += ToIpv4Address(ip->src) + "," +
             ToIpv4Address(ip->src) + "," +
             std::to_string(ip->protocol) + "," +
             std::to_string(sport.value()) +
             std::to_string(dport.value());

      redisReply *reply = (redisReply *)redisCommand(redis_ctx_, "HSET %s %s %d", key.c_str(), field.c_str(), now);
      //printf("HINCRBY: %lld\n", reply->integer);
      freeReplyObject(reply);
    }
  }

  RunNextModule(ctx, batch);
}

void DistributedFlowCounter::Reset() {
  Clear();
  Start();
}

void DistributedFlowCounter::Clear() {
  mcslock_node_t mynode;
  mcs_lock(&lock_, &mynode);

  is_active_ = false;
  usleep(500000); // Sleep for 500 milliseconds.

  if (redis_ctx_) {
    redisReply *reply = (redisReply *)redisCommand(redis_ctx_, "FLUSHDB");
    freeReplyObject(reply);
  }
  flow_cache_.clear();

  mcs_unlock(&lock_, &mynode);
}

void DistributedFlowCounter::Start() {
  mcslock_node_t mynode;
  mcs_lock(&lock_, &mynode);
  is_active_ = true;
  mcs_unlock(&lock_, &mynode);
}

void DistributedFlowCounter::Stop() {
  mcslock_node_t mynode;
  mcs_lock(&lock_, &mynode);
  is_active_ = false;
  mcs_unlock(&lock_, &mynode);
}

CommandResponse DistributedFlowCounter::CommandReset(const bess::pb::EmptyArg &) {
  Reset();
  return CommandResponse();
}

CommandResponse DistributedFlowCounter::CommandClear(const bess::pb::EmptyArg &) {
  Clear();
  return CommandResponse();
}

CommandResponse DistributedFlowCounter::CommandStart(const bess::pb::EmptyArg &) {
  Start();
  return CommandResponse();
}

CommandResponse DistributedFlowCounter::CommandStop(const bess::pb::EmptyArg &) {
  Stop();
  return CommandResponse();
}

CommandResponse DistributedFlowCounter::CommandGetSummary(const bess::pb::EmptyArg &) {
  Stop();

  bess::pb::DistributedFlowCounterGetSummaryRespondArg r;
  std::string s;

  redisReply *reply = (redisReply *)redisCommand(redis_ctx_, "keys FC:*");
  r.set_flow_count(reply->elements);
  for (unsigned j = 0; j < reply->elements; j++) {
    redisReply *rep = (redisReply *)redisCommand(
        redis_ctx_,"HGET %s timestamp", reply->element[j]->str);
    if (rep == nullptr) {
      continue;
    }

    s = std::string("[flow]");
    s += reply->element[j]->str;
    s += std::string(": [timestamp]");
    s += rep->str;
    freeReplyObject(rep);
  }
  freeReplyObject(reply);
  std::cout << s;

  Start();
  return CommandSuccess(r);
}

ADD_MODULE(DistributedFlowCounter, "DistributedFlowCounter",
          "Counts the number of flows observed in a distributed way")
