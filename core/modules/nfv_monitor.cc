#include "nfv_monitor.h"

#include <fstream>

#include "../port.h"
#include "../drivers/pmd.h"
#include "../utils/ether.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/time.h"
#include "../utils/udp.h"

#define DEFAULT_TRAFFIC_STATS_LONG_TERM_UPDATE_PERIOD_NS 200000000 // 200 ms
#define DEFAULT_PER_CORE_MIGRATION_PERIOD_US 200000000 // 200 ms
#define DEFAULT_ACTIVE_FLOW_WINDOW_NS 2000000000 // 2000 ms
#define DEFAULT_PACKET_COUNT_THRESH 1000000
#define DEFAULT_LATENCY_QUEUE_SIZE 10000

namespace {

// The helper function for reading hw timestamp from |pkt| (unit: ns).
uint64_t get_hw_timestamp_nic(bess::Packet *pkt) {
  uint64_t nic_cycle = reinterpret_cast<rte_mbuf*>(pkt)->timestamp;
  return nic_tsc_to_ns(nic_cycle);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

uint64_t get_hw_timestamp_cpu(bess::Packet *pkt) {
  uint64_t nic_cycle = reinterpret_cast<rte_mbuf*>(pkt)->timestamp;
  // Need to get the port name from the user. For now using the first element
  // as we have only 1 port in the test setup.
  Port *port = PortBuilder::all_ports().begin()->second;
  uint64_t cpu_cycle = ((PMDPort*)port)->NICCycleToCPUCycle(nic_cycle);
  return tsc_to_ns(cpu_cycle);
}

#pragma GCC diagnostic pop

} /// namespace

const Commands NFVMonitor::cmds = {
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

  curr_ts_ns_ = tsc_to_ns(rdtsc());
  last_update_traffic_stats_ts_ns_ = curr_ts_ns_;
  next_epoch_id_ = 0;

  update_traffic_stats_period_ns_ = DEFAULT_TRAFFIC_STATS_LONG_TERM_UPDATE_PERIOD_NS;
  if (arg.update_stats_period_ns() > 0) {
    update_traffic_stats_period_ns_ = (uint64_t)arg.update_stats_period_ns();
  }
  LOG(INFO) << "Traffic update period: " << update_traffic_stats_period_ns_;

  // Initialize all elements in the buffer to avoid memory access bugs.
  size_t buffer_size = (arg.latency_sample_buffer_size() > 0) ? arg.latency_sample_buffer_size():DEFAULT_LATENCY_QUEUE_SIZE;
  per_core_latency_sample_.set_capacity(buffer_size);
  for (size_t i = 0; i < buffer_size; i++) {
    per_core_latency_sample_.push_back(0);
  }

  epoch_packet_counter_ = 0;
  epoch_slo_violation_counter_ = 0;
  epoch_packet_delay_error_ = 0;
  epoch_packet_delay_max_ = 0;
  return CommandSuccess();
}

CommandResponse NFVMonitor::CommandClear(const bess::pb::EmptyArg &) {
  per_flow_packet_counter_.clear();
  per_core_latency_sample_.clear();
  return CommandSuccess();
}

void NFVMonitor::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  // using bess::utils::Ethernet;
  // using bess::utils::Ipv4;
  // using bess::utils::Tcp;
  // using bess::utils::Udp;
  // Flow flow;
  // Tcp *tcp = nullptr;
  // Udp *udp = nullptr;

  // We don't use ctx->current_ns here for better accuracy
  curr_ts_ns_ = tsc_to_ns(rdtsc());
  curr_nic_ts_ns_ = nic_tsc_to_ns(nic_rdtsc());

  update_traffic_stats();

  int cnt = batch->cnt();
  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    // Ethernet *eth = pkt->head_data<Ethernet *>();
    // Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);
    // size_t ip_bytes = ip->header_length << 2;

    // if (ip->protocol == Ipv4::Proto::kTcp) {
    //   tcp = reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
    //   flow.src_ip = ip->src;
    //   flow.dst_ip = ip->dst;
    //   flow.src_port = tcp->src_port;
    //   flow.dst_port = tcp->dst_port;
    //   flow.proto_ip = ip->protocol;
    // } else if (ip->protocol == Ipv4::Proto::kUdp) {
    //   udp = reinterpret_cast<Udp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);
    //   flow.src_ip = ip->src;
    //   flow.dst_ip = ip->dst;
    //   flow.src_port = udp->src_port;
    //   flow.dst_port = udp->dst_port;
    //   flow.proto_ip = ip->protocol;
    // } else {
    //   continue;
    // }

    // // Find existing flow, if we have one.
    // std::unordered_map<Flow, uint32_t, FlowHash>::iterator it =
    //     per_flow_packet_counter_.find(flow);

    // if (it == per_flow_packet_counter_.end()) {
    //   per_flow_packet_counter_.emplace(flow, 1);
    // } else {
    //   it->second += 1;
    // }

    // per_core_latency_sample_.push_back(curr_ts_ns_ - get_hw_timestamp_cpu(pkt));
    epoch_packet_counter_ += 1;

    uint64_t pkt_ts_ns = get_hw_timestamp_nic(pkt);
    uint32_t pkt_delay = 0;
    if (curr_nic_ts_ns_ > pkt_ts_ns) {
      pkt_delay = (uint32_t)(curr_nic_ts_ns_ - pkt_ts_ns);
    }

    if (epoch_queue_length_ < 64 && pkt_delay > (uint32_t)5000000) {
      epoch_packet_delay_error_ += 1;
    } else {
      if (pkt_delay > epoch_packet_delay_max_) {
        epoch_packet_delay_max_ = pkt_delay;
      }
      if (pkt_delay > bess::utils::slo_ns) {
        epoch_slo_violation_counter_ += 1;
      }
    }
  }

  RunNextModule(ctx, batch);
}

bool NFVMonitor::update_traffic_stats() {
  using bess::utils::all_local_core_stats;
  using bess::utils::all_core_stats_chan;

  if (curr_ts_ns_ - last_update_traffic_stats_ts_ns_ < update_traffic_stats_period_ns_) {
    return false;
  }

  epoch_queue_length_ = all_local_core_stats[core_id_]->packet_queued;
  active_flow_count_ = all_local_core_stats[core_id_]->active_flow_count;
  packet_rate_ = all_local_core_stats[core_id_]->packet_rate;

  bess::utils::CoreStats *msg = new bess::utils::CoreStats();
  msg->packet_rate = packet_rate_;

  epoch_packet_thresh_ = epoch_packet_counter_ * 0.05;
  if (epoch_slo_violation_counter_ > epoch_packet_counter_ * 0.01) {
    for (auto &it : per_flow_packet_counter_) {
      if (it.second > epoch_packet_thresh_) {
        msg->bursty_flows.push_back(it.first);
      }
    }
  }
  all_core_stats_chan[core_id_]->Push(msg);

  if (packet_rate_ > 0.1) {
    core_snapshots_.push_back(CoreSnapshot{epoch_id: next_epoch_id_});
    core_snapshots_[next_epoch_id_].epoch_size = (uint32_t)(curr_ts_ns_ - last_update_traffic_stats_ts_ns_);
    core_snapshots_[next_epoch_id_].slo_violation = epoch_slo_violation_counter_;
    core_snapshots_[next_epoch_id_].packet_delay_error = epoch_packet_delay_error_;
    core_snapshots_[next_epoch_id_].packet_delay_max = epoch_packet_delay_max_;
    core_snapshots_[next_epoch_id_].active_flow_count = all_local_core_stats[core_id_]->active_flow_count;
    core_snapshots_[next_epoch_id_].bursty_flow_count = msg->bursty_flows.size();

    core_snapshots_[next_epoch_id_].packet_rate = all_local_core_stats[core_id_]->packet_rate;
    core_snapshots_[next_epoch_id_].packet_processed = all_local_core_stats[core_id_]->packet_processed;
    core_snapshots_[next_epoch_id_].packet_queued = all_local_core_stats[core_id_]->packet_queued;
    next_epoch_id_ += 1;
  }

  // Reset epoch
  per_flow_packet_counter_.clear();
  epoch_packet_counter_ = 0;
  epoch_slo_violation_counter_ = 0;
  epoch_packet_delay_error_ = 0;
  epoch_packet_delay_max_ = 0;
  last_update_traffic_stats_ts_ns_ = curr_ts_ns_;
  return true;
}

CommandResponse NFVMonitor::CommandGetSummary(const bess::pb::EmptyArg &) {
  std::string fname = "stats" + std::to_string(core_id_) + ".txt";
  std::ofstream out_fp(fname);
  if (out_fp.is_open()) {
    out_fp << "Per core stats:" << std::endl;
    for (size_t i = 0; i < core_snapshots_.size(); i++) {
      out_fp << "epoch:" << i;
      out_fp << ", size:" << core_snapshots_[i].epoch_size;
      out_fp << ", core:" << (core_snapshots_[i].packet_rate > 0.1 ? 1 : 0);
      out_fp << ", slo:" << core_snapshots_[i].slo_violation;
      out_fp << ", delaye:" << core_snapshots_[i].packet_delay_error;
      out_fp << ", delaym:" << core_snapshots_[i].packet_delay_max;
      out_fp << ", flowa:" << core_snapshots_[i].active_flow_count;
      out_fp << ", flowb:" << core_snapshots_[i].bursty_flow_count;
      out_fp << ", rate:" << core_snapshots_[i].packet_rate;
      out_fp << ", pktp:" << core_snapshots_[i].packet_processed;
      out_fp << ", pktq:" << core_snapshots_[i].packet_queued;
      out_fp << std::endl;
    }
  }

  out_fp << "P50 latency:" << GetTailLatency(50) << std::endl;
  out_fp << "P99 latency:" << GetTailLatency(99) << std::endl;

  out_fp.close();
  return CommandResponse();
}

ADD_MODULE(NFVMonitor, "nfv_monitor", "It collects traffic statistics at each core")
