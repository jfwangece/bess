#include "nfv_monitor.h"

#include <fstream>

#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/udp.h"

#define DEFAULT_TRAFFIC_STATS_UPDATE_PERIOD_NS 200000000 // 200 ms
#define DEFAULT_PER_CORE_MIGRATION_PERIOD_US 200000000 // 200 ms
#define DEFAULT_ACTIVE_FLOW_WINDOW_NS 2000000000 // 2000 ms
#define DEFAULT_PACKET_COUNT_THRESH 1000000

namespace {
const uint64_t TIME_OUT_NS = 10ull * 1000 * 1000 * 1000; // 10 seconds
}

const Commands NFVMonitor::cmds = {
    {"add", "NFVMonitorArg", MODULE_CMD_FUNC(&NFVMonitor::CommandAdd),
     Command::THREAD_UNSAFE},
    {"get_summary", "EmptyArg", MODULE_CMD_FUNC(&NFVMonitor::CommandGetSummary),
     Command::THREAD_SAFE},
    {"clear", "EmptyArg", MODULE_CMD_FUNC(&NFVMonitor::CommandClear),
     Command::THREAD_UNSAFE},
};

CommandResponse NFVMonitor::Init([[maybe_unused]]const bess::pb::NFVMonitorArg &arg) {
  core_id_ =0;
  if (arg.core_id() > 0) {
    core_id_ = arg.core_id();
  }

  curr_ts_ns_ = 0;
  last_update_traffic_stats_ts_ns_ = 0;
  next_epoch_id_ = 0;

  update_traffic_stats_period_ns_ = DEFAULT_TRAFFIC_STATS_UPDATE_PERIOD_NS;
  if (arg.update_stats_period_ns() > 0) {
    update_traffic_stats_period_ns_ = (uint64_t)arg.update_stats_period_ns();
  }
  LOG(INFO) << "Traffic update period: " << update_traffic_stats_period_ns_;

  per_core_packet_counter_ = 0;

  return CommandSuccess();
}

CommandResponse NFVMonitor::CommandAdd([[maybe_unused]]const bess::pb::NFVMonitorArg &arg) {
  return CommandSuccess();
}

CommandResponse NFVMonitor::CommandClear(const bess::pb::EmptyArg &) {
  per_flow_packet_counter_.clear();
  return CommandSuccess();
}

void NFVMonitor::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  using bess::utils::Ethernet;
  using bess::utils::Ipv4;
  using bess::utils::Tcp;
  using bess::utils::Udp;

  Flow flow;
  Tcp *tcp = nullptr;
  Udp *udp = nullptr;

  curr_ts_ns_ = ctx->current_ns;

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    size_t ip_bytes = ip->header_length << 2;

    if (ip->protocol == Ipv4::Proto::kTcp) {
      tcp = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
      flow.src_ip = ip->src;
      flow.dst_ip = ip->dst;
      flow.src_port = tcp->src_port;
      flow.dst_port = tcp->dst_port;
      flow.proto_ip = ip->protocol;
    } else if (ip->protocol == Ipv4::Proto::kUdp) {
      udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
      flow.src_ip = ip->src;
      flow.dst_ip = ip->dst;
      flow.src_port = udp->src_port;
      flow.dst_port = udp->dst_port;
      flow.proto_ip = ip->protocol;
    } else {
      continue;
    }

    // Find existing flow, if we have one.
    std::unordered_map<Flow, uint64_t, FlowHash>::iterator it =
        per_flow_packet_counter_.find(flow);

    if (it == per_flow_packet_counter_.end()) {
      per_flow_packet_counter_.emplace(flow, 1);
    } else {
      it->second += 1;
    }
    per_core_packet_counter_ += 1;
  }

  RunNextModule(ctx, batch);
}

bool NFVMonitor::update_traffic_stats() {
  if (curr_ts_ns_ - last_update_traffic_stats_ts_ns_ < update_traffic_stats_period_ns_) {
    return false;
  }

  int sum_active_cores = 0;
  uint64_t sum_rate = 0;
  // Update |active_flow_count|, |packet_rate| for each CPU core
  active_flow_count_ = per_flow_packet_counter_.size();
  packet_rate_ = per_core_packet_counter_;
  per_flow_packet_counter_.clear();
  per_core_packet_counter_ = 0;

  if (packet_rate_ > 0) {
    sum_active_cores += 1;
    sum_rate += packet_rate_;
  }
  cluster_snapshots_[next_epoch_id_].per_core_packet_rate.push_back(packet_rate_);

  if (sum_rate > 0) {
    cluster_snapshots_[next_epoch_id_].active_core_count = sum_active_cores;
    cluster_snapshots_[next_epoch_id_].sum_packet_rate = sum_rate;
    ++next_epoch_id_;
  } else {
    // Do not record if the cluster is not processing any packets
    cluster_snapshots_.pop_back();
  }

  last_update_traffic_stats_ts_ns_ = curr_ts_ns_;
  return true;
}

CommandResponse NFVMonitor::CommandGetSummary(const bess::pb::EmptyArg &) {
  int total_flows = per_flow_packet_counter_.size();

  int sum_cores = 0;
  int total_epochs = cluster_snapshots_.size();
  for (auto & x : cluster_snapshots_) {
    sum_cores += x.active_core_count;
  }

  std::ofstream out_fp("stats.txt");
  if (out_fp.is_open()) {
    // Traffic
    out_fp << "Flow stats:" << std::endl;
    out_fp << "- Total flows: " << total_flows << std::endl;
    out_fp << std::endl;

    // CPU cores
    out_fp << "CPU core stats:" << std::endl;
    out_fp << "- Total epochs: " << total_epochs << std::endl;
    out_fp << "- Time-avg cores: " << double(sum_cores) / double(total_epochs) << std::endl;
    out_fp << std::endl;

    for (size_t i = 0; i < cluster_snapshots_.size(); i++) {
      out_fp << "epoch:" << i << ", core:" << cluster_snapshots_[i].active_core_count << ", rate:" << cluster_snapshots_[i].sum_packet_rate << std::endl;
    }
  }

  out_fp << std::endl;
  out_fp.close();

  return CommandResponse();
}

ADD_MODULE(NFVMonitor, "nfv_monitor", "It collects traffic statistics at each core")
