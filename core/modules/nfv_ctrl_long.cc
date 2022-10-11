#include "nfv_ctrl.h"
#include "nfv_ctrl_msg.h"

#include "../utils/checksum.h"
#include "../utils/sys_measure.h"

// The amount of space to leave when packing buckets into CPUs
#define MIGRATE_HEAD_ROOM 0.1
#define ASSIGN_HEAD_ROOM 0.2

namespace {
// Template for generating TCP packets without data
struct[[gnu::packed]] PacketTemplate {
  Ethernet eth;
  Ipv4 ip;
  Tcp tcp;

  PacketTemplate() {
    eth.dst_addr = Ethernet::Address();  // To fill in
    eth.src_addr = Ethernet::Address();  // To fill in
    eth.ether_type = be16_t(Ethernet::Type::kIpv4);
    ip.version = 4;
    ip.header_length = 5;
    ip.type_of_service = 0;
    ip.length = be16_t(40);
    ip.id = be16_t(0);  // To fill in
    ip.fragment_offset = be16_t(0);
    ip.ttl = 0x40;
    ip.protocol = Ipv4::Proto::kTcp;
    ip.checksum = 0;           // To fill in
    ip.src = be32_t(0);        // To fill in
    ip.dst = be32_t(0);        // To fill in
    tcp.src_port = be16_t(0);  // To fill in
    tcp.dst_port = be16_t(0);  // To fill in
    tcp.seq_num = be32_t(0);   // To fill in
    tcp.ack_num = be32_t(0);   // To fill in
    tcp.reserved = 0x01;
    tcp.offset = 5;
    tcp.flags = Tcp::Flag::kAck | Tcp::Flag::kRst;
    tcp.window = be16_t(0);
    tcp.checksum = 0;  // To fill in
    tcp.urgent_ptr = be16_t(0);
  }
};
static PacketTemplate info_template;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
// Query the Gurobi optimization server to get a core assignment scheme.
void WriteToGurobi(uint32_t num_cores, std::vector<float> flow_rates, float latency_bound) {
  LOG(INFO) << num_cores << flow_rates.size() << latency_bound;
  std::ofstream file_out;
  file_out.open("./gurobi_in");
  file_out << num_cores <<std::endl;
  file_out << flow_rates.size() << std::endl;
  file_out << std::fixed <<latency_bound <<std::endl;
  for (auto& it : flow_rates) {
    file_out << it<< std::endl;
  }
  file_out.close();
}
#pragma GCC diagnostic pop
} // namespace

void NFVCtrl::InitPMD(PMDPort* port) {
  if (port == nullptr) {
    return;
  }

  port_ = port;
  // Reset PMD's reta table (even-distributed RSS buckets)
  for (uint16_t i = 0; i < port_->reta_size_; i++) {
    port_->reta_table_[i] = i % total_core_count_;
  }

  local_batch_ = reinterpret_cast<bess::PacketBatch *>
          (std::aligned_alloc(alignof(bess::PacketBatch), sizeof(bess::PacketBatch)));
  if (!local_batch_) {
    LOG(FATAL) << "Failed to alloc a local batch at NFVCtrl.";
    return;
  }
  local_batch_->clear();

  // Init the core-bucket mapping
  for (uint16_t i = 0; i < total_core_count_; i++) {
    core_bucket_mapping_[i] = std::vector<uint16_t>();
  }
  for (uint16_t i = 0; i < port_->reta_size_; i++) {
    uint16_t core_id = port_->reta_table_[i];
    core_bucket_mapping_[core_id].push_back(i);
  }

  // Init the number of |active_core_count_|
  active_core_count_ = 0;
  for (uint16_t i = 0; i < total_core_count_; i++) {
    if (core_bucket_mapping_[i].size() > 0) {
      bess::ctrl::core_state[i] = true;
      active_core_count_ += 1;
    }
  }
  rte_atomic16_set(&curr_active_core_count_, active_core_count_);

  LOG(INFO) << "NIC init: " << active_core_count_ << " active normal cores";
  // port_->UpdateRssReta();
  port_->UpdateRssFlow();
}

std::map<uint16_t, uint16_t> NFVCtrl::FindMoves(std::vector<double>& per_cpu_pkt_rate,
                                                std::vector<double>& per_cpu_flow_count,
                                                const std::vector<double>& per_bucket_pkt_rate,
                                                const std::vector<double>& per_bucket_flow_count,
                                                std::vector<uint16_t>& to_move_buckets) {
  std::map<uint16_t, uint16_t> moves;
  for (auto bucket : to_move_buckets) {
    double bucket_pkt_rate = per_bucket_pkt_rate[bucket];
    double bucket_flow_count = per_bucket_flow_count[bucket];
    bool found = false;
    for (uint16_t i = 0; i < total_core_count_; i++) {
      if (bess::ctrl::nfv_cores[i] &&
          bess::ctrl::core_state[i] &&
          per_cpu_pkt_rate[i] + bucket_pkt_rate <
          (GetMaxPktRateFromLongTermProfile(per_cpu_flow_count[i] + bucket_flow_count) * (1 - ASSIGN_HEAD_ROOM))) {
        per_cpu_pkt_rate[i] += bucket_pkt_rate;
        per_cpu_flow_count[i] += bucket_flow_count;
        moves[bucket] = i;
        core_bucket_mapping_[i].push_back(bucket);
        found = true;
        break;
      }
    }

    // No core found. Need to add a new core
    if (!found) {
      for (uint16_t i = 0; i < total_core_count_; i++) {
        if (bess::ctrl::nfv_cores[i] && !bess::ctrl::core_state[i]) {
          per_cpu_pkt_rate[i] += bucket_pkt_rate;
          per_cpu_flow_count[i] += bucket_flow_count;
          moves[bucket] = i;
          core_bucket_mapping_[i].push_back(bucket);
          found = true;

          bess::ctrl::core_state[i] = true;
          bess::ctrl::core_liveness[i] = 1;
          active_core_count_ += 1;
          break;
        }
      }

      // No enough cores for handling the excessive load. Ideally, this should never happen
      if (!found) {
        LOG(INFO) << "No idle normal core found for bucket: " << bucket << " w/ rate: " << bucket_pkt_rate;
      }
    }
  }
  return moves;
}

double NFVCtrl::GetMaxPktRateFromLongTermProfile(double fc) {
  if (bess::ctrl::long_flow_count_pps_threshold.size() == 0) {
    return 1000000.0;
  }

  for (auto& it : bess::ctrl::long_flow_count_pps_threshold) {
    if (it.first > fc) {
      return it.second;
    }
  }
  return (--bess::ctrl::long_flow_count_pps_threshold.end())->second;
}

std::map<uint16_t, uint16_t> NFVCtrl::LongTermOptimization(
    const std::vector<double>& per_bucket_pkt_rate,
    const std::vector<double>& per_bucket_flow_count) {

  active_core_count_ = 0;
  std::vector<double> per_cpu_pkt_rate(total_core_count_);
  std::vector<double> per_cpu_flow_count(total_core_count_);

  // Compute the aggregated packet rate for each core.
  // Note: |core_state|: a normal core is in-use;
  // |core_liveness|: # of long-term epochs that a core has been active
  for (uint16_t i = 0; i < total_core_count_; i++) {
    per_cpu_pkt_rate[i] = 0;
    if (core_bucket_mapping_[i].size() > 0) {
      for (auto it : core_bucket_mapping_[i]) {
        per_cpu_pkt_rate[i] += per_bucket_pkt_rate[it];
        per_cpu_flow_count[i] += per_bucket_flow_count[it];
      }
      bess::ctrl::core_state[i] = true;
      bess::ctrl::core_liveness[i] += 1;
      active_core_count_ += 1;
    }
  }

  // Find if any core is exceeding threshold and add it to the to be moved list
  std::vector<uint16_t> to_move_buckets;
  for (uint16_t i = 0; i < total_core_count_; i++) {
    if (!bess::ctrl::core_state[i]) {
      continue;
    }
    // LOG(INFO) << i << ", " << per_cpu_flow_count[i] << ", " << GetMaxPktRateFromLongTermProfile(per_cpu_flow_count[i]);
    // Move a bucket and do this until the aggregated packet rate is below the threshold
    while (per_cpu_pkt_rate[i] >
          GetMaxPktRateFromLongTermProfile(per_cpu_flow_count[i]) * (1 - MIGRATE_HEAD_ROOM) &&
          core_bucket_mapping_[i].size() > 0) {
      uint16_t bucket = core_bucket_mapping_[i].back();
      to_move_buckets.push_back(bucket);
      core_bucket_mapping_[i].pop_back();

      per_cpu_pkt_rate[i] -= per_bucket_pkt_rate[bucket];
      per_cpu_flow_count[i] -= per_bucket_flow_count[bucket];
      bess::ctrl::core_liveness[i] = 1;
    }
  }

  // For all buckets to be moved, assign them to a core
  std::map<uint16_t, uint16_t> final_moves = FindMoves(
      per_cpu_pkt_rate, per_cpu_flow_count,
      per_bucket_pkt_rate, per_bucket_flow_count,
      to_move_buckets);

  if (active_core_count_ == 1) {
    return final_moves;
  }

  // Find the CPU with minimum flow rate and (try to) delete it
  uint16_t min_rate_core = DEFAULT_INVALID_CORE_ID;
  double min_rate = 0;
  for(uint16_t i = 0; i < total_core_count_; i++) {
    if (!bess::ctrl::core_state[i] ||
        bess::ctrl::core_liveness[i] <= 4) {
      continue;
    }

    if (min_rate_core == DEFAULT_INVALID_CORE_ID) {
      min_rate_core = i;
      min_rate = per_cpu_pkt_rate[i];
      continue;
    }
    if (per_cpu_pkt_rate[i] < min_rate) {
      min_rate_core = i;
      min_rate = per_cpu_pkt_rate[i];
    }
  }

  // Do nothing to avoid oscillations. If:
  // - no min-rate core is found;
  // - the min-rate core's rate is too large;
  if (min_rate_core == DEFAULT_INVALID_CORE_ID ||
      min_rate > GetMaxPktRateFromLongTermProfile(per_cpu_flow_count[min_rate_core]) / 2) {
    return final_moves;
  }

  // Move all buckets at the min-rate core; before that, save the current state
  per_cpu_pkt_rate[min_rate_core] = 100000000;
  int org_active_cores = active_core_count_;
  std::vector<uint16_t> org_buckets = core_bucket_mapping_[min_rate_core];

  std::map<uint16_t, uint16_t> tmp_moves = FindMoves(
      per_cpu_pkt_rate, per_cpu_flow_count,
      per_bucket_pkt_rate, per_bucket_flow_count,
      core_bucket_mapping_[min_rate_core]);

  if (active_core_count_ > org_active_cores ||
      tmp_moves.size() != org_buckets.size()) {
    // If this trial fails, undo all changes
    // - case 1: |FindMoves| uses more cores;
    // - case 2: |org_buckets| cannot be fit into normal cores;
    per_cpu_pkt_rate[min_rate_core] = min_rate;
    for (auto& m_it : tmp_moves) {
      core_bucket_mapping_[m_it.second].pop_back();
      per_cpu_pkt_rate[m_it.second] -= per_bucket_pkt_rate[m_it.first];
      per_cpu_flow_count[m_it.second] -= per_bucket_flow_count[m_it.first];
    }
  } else {
    // Reclaim the min-rate core successfully
    core_bucket_mapping_[min_rate_core].clear();
    for (auto& m_it : tmp_moves) {
      final_moves[m_it.first] = m_it.second;
    }

    bess::ctrl::core_state[min_rate_core] = false;
    active_core_count_ -= 1;
  }

  return final_moves;
}

uint32_t NFVCtrl::LongEpochProcess() {
  uint64_t to_rate_per_sec = 1000000000ULL / (tsc_to_ns(rdtsc()) - last_long_epoch_end_ns_);

  // Per-bucket packet rate and flow count are to be used by the long-term op.
  std::vector<double> per_bucket_pkt_rate;
  std::vector<double> per_bucket_flow_count;

  bess::utils::bucket_stats->bucket_table_lock.lock();
  for (int i = 0; i < RETA_SIZE; i++) {
    per_bucket_pkt_rate.push_back(bess::utils::bucket_stats->per_bucket_packet_counter[i] * to_rate_per_sec);
    per_bucket_flow_count.push_back(bess::utils::bucket_stats->per_bucket_flow_cache[i].size() * to_rate_per_sec);
    bess::utils::bucket_stats->per_bucket_packet_counter[i] = 0;
    bess::utils::bucket_stats->per_bucket_flow_cache[i].clear();
  }
  bess::utils::bucket_stats->bucket_table_lock.unlock();

  std::map<uint16_t, uint16_t> moves = LongTermOptimization(per_bucket_pkt_rate, per_bucket_flow_count);
  rte_atomic16_set(&curr_active_core_count_, active_core_count_);
  SendWorkerInfo();

  if (moves.size()) {
    if (port_) {
      // port_->UpdateRssReta(moves);
      port_->UpdateRssFlow(moves);
    }
  }
  return moves.size();
}

void NFVCtrl::SendWorkerInfo() {
  const queue_t qid = ACCESS_ONCE(qid_);
  int pktcnt = 3;

  local_batch_->clear();
  for (int i = 0; i < pktcnt; i++) {
    bess::Packet* pkt = current_worker.packet_pool()->Alloc();    
    char *p = pkt->buffer<char *>() + SNBUF_HEADROOM;
    pkt->set_data_off(SNBUF_HEADROOM);
    pkt->set_total_len(sizeof(info_template));
    pkt->set_data_len(sizeof(info_template));
    bess::utils::Copy(p, &info_template, sizeof(info_template));

    Ethernet* eth = reinterpret_cast<Ethernet *>(p);
    Ipv4* ip = reinterpret_cast<Ipv4 *>(eth + 1);
    Tcp* tcp = reinterpret_cast<Tcp *>(ip + 1);

    eth->src_addr = Ethernet::Address("ec:0d:9a:67:ff:68");
    eth->dst_addr = Ethernet::Address("b4:96:91:b3:89:b4");
    ip->src = be32_t(0x0a0a0102);
    ip->dst = be32_t(0x0a0a0101);
    ip->length = be16_t(40);
    tcp->src_port = be16_t(uint16_t(worker_id_)); // whoami
    tcp->dst_port = be16_t(active_core_count_); // # of normal cores
    tcp->seq_num = be32_t(worker_id_);
    tcp->ack_num = be32_t(active_core_count_);
    tcp->flags = Tcp::Flag::kSyn;

    tcp->checksum = CalculateIpv4TcpChecksum(*ip, *tcp);
    ip->checksum = CalculateIpv4Checksum(*ip);
    local_batch_->add(pkt);
  }

  port_->SendPackets(qid, local_batch_->pkts(), pktcnt);
}
