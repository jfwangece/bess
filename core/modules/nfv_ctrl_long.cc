#include "nfv_core.h"
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
  // start with 0.5x CPU core load
  active_core_count_ = total_core_count_ / 2;
  if (active_core_count_ == 0) {
    active_core_count_ = 1;
  }

  // Reset PMD's reta table (even-distributed RSS buckets)
  for (uint16_t i = 0; i < port_->reta_size_; i++) {
    port_->reta_table_[i] = (i / RETA_TO_SHARD) % active_core_count_;
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
    core_shard_mapping_[i] = std::vector<uint16_t>();
  }
  for (uint16_t i = 0; i < SHARD_NUM; i++) {
    uint16_t core_id = port_->reta_table_[i * RETA_TO_SHARD];
    core_shard_mapping_[core_id].push_back(i);
  }

  // Init the number of |active_core_count_|
  active_core_count_ = 0;
  for (uint16_t i = 0; i < total_core_count_; i++) {
    if (core_shard_mapping_[i].size() > 0) {
      bess::ctrl::core_state[i] = true;
      active_core_count_ += 1;
    }
  }
  rte_atomic16_set(&curr_active_core_count_, active_core_count_);

  LOG(INFO) << "NIC init: " << active_core_count_ << " active normal cores";
  // port_->UpdateRssReta();
  port_->UpdateRssFlow();
}

uint64_t GetMaxPktRateFromLongTermProfile(uint64_t fc) {
  if (bess::ctrl::long_flow_count_pps_threshold.size() == 0) {
    return 1000000;
  }

  for (auto& it : bess::ctrl::long_flow_count_pps_threshold) {
    if (it.first > fc) {
      return it.second;
    }
  }
  return (--bess::ctrl::long_flow_count_pps_threshold.end())->second;
}

std::map<uint16_t, uint16_t> NFVCtrl::FindMoves(std::vector<uint64_t>& per_cpu_pkt_rate,
                                                std::vector<uint64_t>& per_cpu_flow_count,
                                                const std::vector<uint64_t>& per_shard_pkt_rate,
                                                const std::vector<uint64_t>& per_shard_flow_count,
                                                std::vector<uint16_t>& to_move_shards) {
  std::map<uint16_t, uint16_t> moves;
  std::vector<uint16_t> skipped_shards;
  uint64_t shard_pkt_rate, shard_flow_count;

  for (auto shard : to_move_shards) {
    shard_pkt_rate = per_shard_pkt_rate[shard];
    shard_flow_count = per_shard_flow_count[shard];
    bool found = false;
    for (uint16_t i = 0; i < total_core_count_; i++) {
      if (bess::ctrl::nfv_cores[i] &&
          bess::ctrl::core_state[i] &&
          per_cpu_pkt_rate[i] + shard_pkt_rate <
          (GetMaxPktRateFromLongTermProfile(per_cpu_flow_count[i] + shard_flow_count) * (1 - ASSIGN_HEAD_ROOM))) {
        per_cpu_pkt_rate[i] += shard_pkt_rate;
        per_cpu_flow_count[i] += shard_flow_count;
        moves[shard] = i;
        core_shard_mapping_[i].push_back(shard);
        found = true;
        break;
      }
    }

    // No core found. Need to add a new core
    if (!found) {
      for (uint16_t i = 0; i < total_core_count_; i++) {
        if (bess::ctrl::nfv_cores[i] &&
            !bess::ctrl::core_state[i]) {
          per_cpu_pkt_rate[i] += shard_pkt_rate;
          per_cpu_flow_count[i] += shard_flow_count;
          moves[shard] = i;
          core_shard_mapping_[i].push_back(shard);
          found = true;

          bess::ctrl::core_state[i] = true;
          bess::ctrl::core_liveness[i] = 1;
          active_core_count_ += 1;
          break;
        }
      }

      // No enough cores for handling the excessive load. (This should never happen)
      if (!found) {
        skipped_shards.push_back(shard);
      }
    }
  }

  to_move_shards = skipped_shards;
  size_t skip = to_move_shards.size();
  if (skip > 0) {
    LOG(INFO) << "No idle ncore found for " << skip << " buckets; active ncores: " << active_core_count_;
  }
  return moves;
}

std::map<uint16_t, uint16_t> NFVCtrl::LongTermOptimization(
        const std::vector<uint64_t>& per_shard_pkt_rate,
        const std::vector<uint64_t>& per_shard_flow_count) {
  std::vector<uint64_t> per_cpu_pkt_rate(total_core_count_);
  std::vector<uint64_t> per_cpu_flow_count(total_core_count_);
  active_core_count_ = 0;

  // Compute the aggregated packet rate for each core.
  // Note: |core_state|: a normal core is in-use;
  // |core_liveness|: # of long-term epochs that a core has been active
  for (uint16_t i = 0; i < total_core_count_; i++) {
    per_cpu_pkt_rate[i] = 0;
    per_cpu_flow_count[i] = 0;
    if (core_shard_mapping_[i].size() > 0) {
      for (uint16_t shard : core_shard_mapping_[i]) {
        per_cpu_pkt_rate[i] += per_shard_pkt_rate[shard];
        per_cpu_flow_count[i] += per_shard_flow_count[shard];
      }
      bess::ctrl::core_state[i] = true;
      bess::ctrl::core_liveness[i] += 1;
      active_core_count_ += 1;
    }
  }

  // Find if any core is exceeding threshold and add it to the to be moved list
  std::vector<uint16_t> to_move_shards;
  std::map<uint16_t, uint16_t> to_move_shards_to_cores; // remember where to put back
  for (uint16_t i = 0; i < total_core_count_; i++) {
    if (!bess::ctrl::core_state[i]) {
      continue;
    }
    LOG(INFO) << "c" << i << ": " << per_cpu_pkt_rate[i] << ", " << per_cpu_flow_count[i] << ", " << GetMaxPktRateFromLongTermProfile(per_cpu_flow_count[i]);

    // Move a bucket and do this until the aggregated packet rate is below the threshold
    while (per_cpu_pkt_rate[i] >
          GetMaxPktRateFromLongTermProfile(per_cpu_flow_count[i]) * (1 - MIGRATE_HEAD_ROOM) &&
          core_shard_mapping_[i].size() > 0) {
      uint16_t bucket = core_shard_mapping_[i].back();
      to_move_shards.push_back(bucket);
      to_move_shards_to_cores.emplace(bucket, i);
      core_shard_mapping_[i].pop_back();

      per_cpu_pkt_rate[i] -= per_shard_pkt_rate[bucket];
      per_cpu_flow_count[i] -= per_shard_flow_count[bucket];
      bess::ctrl::core_liveness[i] = 1;
    }
  }

  // For all shards to be moved, assign them to a core
  std::map<uint16_t, uint16_t> shard_moves = FindMoves(
      per_cpu_pkt_rate, per_cpu_flow_count,
      per_shard_pkt_rate, per_shard_flow_count,
      to_move_shards);

  // Keep track of these shards
  for (auto shard : to_move_shards) {
    uint16_t core = to_move_shards_to_cores[shard];
    core_shard_mapping_[core].push_back(shard);
    per_cpu_pkt_rate[core] += per_shard_pkt_rate[shard];
    per_cpu_flow_count[core] += per_shard_flow_count[shard];
  }

  if (active_core_count_ == 1) {
    return shard_moves;
  }

  // Find the CPU with minimum flow rate and (try to) delete it
  uint16_t min_rate_core = DEFAULT_INVALID_CORE_ID;
  uint64_t min_rate = 0;
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
    return shard_moves;
  }

  // Move all buckets at the min-rate core; before that, save the current state
  per_cpu_pkt_rate[min_rate_core] = 100000000;
  int org_active_cores = active_core_count_;
  std::vector<uint16_t> pack_shards = core_shard_mapping_[min_rate_core];
  size_t pack_shard_cnt = pack_shards.size();

  std::map<uint16_t, uint16_t> tmp_shard_moves = FindMoves(
      per_cpu_pkt_rate, per_cpu_flow_count,
      per_shard_pkt_rate, per_shard_flow_count,
      pack_shards);

  if (active_core_count_ > org_active_cores ||
      pack_shards.size() > 0 ||
      tmp_shard_moves.size() != pack_shard_cnt) {
    // If this trial fails, undo all changes
    // - case 1: |FindMoves| uses more cores;
    // - case 2: |pack_shards| cannot be fit into normal cores;
    per_cpu_pkt_rate[min_rate_core] = min_rate;
    for (auto& m_it : tmp_shard_moves) {
      core_shard_mapping_[m_it.second].pop_back();
      per_cpu_pkt_rate[m_it.second] -= per_shard_pkt_rate[m_it.first];
      per_cpu_flow_count[m_it.second] -= per_shard_flow_count[m_it.first];
    }
  } else {
    // Reclaim the min-rate core successfully
    core_shard_mapping_[min_rate_core].clear();
    for (auto& m_it : tmp_shard_moves) {
      shard_moves[m_it.first] = m_it.second;
    }

    bess::ctrl::core_state[min_rate_core] = false;
    active_core_count_ -= 1;
  }

  return shard_moves;
}

uint32_t NFVCtrl::LongEpochProcess() {
  // Per-bucket packet rate and flow count used by the long-term optimization.
  std::vector<uint64_t> per_shard_pkt_rate(SHARD_NUM, 0);
  std::vector<uint64_t> per_shard_flow_count(SHARD_NUM, 0);
  uint64_t pps = 0;
  uint64_t to_rate_per_sec = 1000000000ULL / (tsc_to_ns(rdtsc()) - last_long_epoch_end_ns_);
  LOG(INFO) << "const (to_rps):" << to_rate_per_sec;

  for (int j = 0; j < bess::ctrl::ncore; j++) {
    for (int i = 0; i < SHARD_NUM; i++) {
      per_shard_pkt_rate[i] += bess::ctrl::pcpb_packet_count[j][i];
      per_shard_flow_count[i] += bess::ctrl::pcpb_flow_count[j][i];
    }
  }
  for (int i = 0; i < SHARD_NUM; i++) {
    per_shard_pkt_rate[i] *= to_rate_per_sec;
    per_shard_flow_count[i] *= to_rate_per_sec;
    pps += per_shard_pkt_rate[i];
  }
  curr_packet_rate_ = (uint32_t)pps;

  std::map<uint16_t, uint16_t> moves =
    LongTermOptimization(per_shard_pkt_rate, per_shard_flow_count);

  rte_atomic16_set(&curr_active_core_count_, active_core_count_);
  SendWorkerInfo();

  if (moves.size() && port_) {
    bess::ctrl::nfvctrl_bucket_mu.lock();
    bess::ctrl::trans_buckets = moves;
    bess::ctrl::nfvctrl_bucket_mu.unlock();

    port_->UpdateRssFlow(moves);
    LOG(INFO) << "default; moves=" << moves.size() << ", cores=" << active_core_count_;
  }
  return moves.size();
}

std::map<uint16_t, uint16_t> NFVCtrl::OnDemandLongTermOptimization(uint16_t core_id,
        const std::vector<uint64_t>& per_shard_pkt_rate,
        const std::vector<uint64_t>& per_shard_flow_count) {
  std::vector<uint64_t> per_cpu_pkt_rate(total_core_count_);
  std::vector<uint64_t> per_cpu_flow_count(total_core_count_);

  for (uint16_t i = 0; i < total_core_count_; i++) {
    per_cpu_pkt_rate[i] = 0;
    if (core_shard_mapping_[i].size() > 0) {
      for (auto it : core_shard_mapping_[i]) {
        per_cpu_pkt_rate[i] += per_shard_pkt_rate[it];
        per_cpu_flow_count[i] += per_shard_flow_count[it];
      }
      bess::ctrl::core_state[i] = true;
      bess::ctrl::core_liveness[i] += 1;
    }
  }

  // Add buckets to |to_move_shards|.
  std::vector<uint16_t> to_move_shards;
  uint64_t target_pkt_rate = per_cpu_pkt_rate[core_id] / 2;
  while (per_cpu_pkt_rate[core_id] > target_pkt_rate &&
        core_shard_mapping_[core_id].size() > 0) {
    uint16_t bucket = core_shard_mapping_[core_id].back();
    to_move_shards.push_back(bucket);
    core_shard_mapping_[core_id].pop_back();

    per_cpu_pkt_rate[core_id] -= per_shard_pkt_rate[bucket];
    per_cpu_flow_count[core_id] -= per_shard_flow_count[bucket];
    bess::ctrl::core_liveness[core_id] = 1;
  }

  uint16_t mr_core = DEFAULT_INVALID_CORE_ID;
  uint64_t min_rate = 0;
  for(uint16_t i = 0; i < total_core_count_; i++) {
    if (bess::ctrl::nfv_cores[i]) {
      if (mr_core == DEFAULT_INVALID_CORE_ID) {
        mr_core = i;
        min_rate = per_cpu_pkt_rate[i];
        continue;
      }
      if (per_cpu_pkt_rate[i] < min_rate) {
        mr_core = i;
        min_rate = per_cpu_pkt_rate[i];
      }
    }
  }

  if (!bess::ctrl::core_state[mr_core]) {
    bess::ctrl::core_state[mr_core] = true;
    bess::ctrl::core_liveness[mr_core] = 1;
    active_core_count_ += 1;
  }

  std::map<uint16_t, uint16_t> moves;
  for (auto bucket : to_move_shards) {
    per_cpu_pkt_rate[mr_core] += per_shard_pkt_rate[bucket];
    per_cpu_flow_count[mr_core] += per_shard_flow_count[bucket];
    moves[bucket] = mr_core;
    core_shard_mapping_[mr_core].push_back(bucket);
  }
  return moves;
}

uint32_t NFVCtrl::OnDemandLongEpochProcess(uint16_t core_id) {
  // Per-bucket packet rate and flow count are to be used by the long-term op.
  std::vector<uint64_t> per_shard_pkt_rate;
  std::vector<uint64_t> per_shard_flow_count;

  uint64_t to_rate_per_sec = 1000000000ULL / (tsc_to_ns(rdtsc()) - last_long_epoch_end_ns_);
  uint64_t pps = 0;
  bess::utils::bucket_stats->bucket_table_lock.lock();
  for (int i = 0; i < SHARD_NUM; i++) {
    per_shard_pkt_rate.push_back(bess::utils::bucket_stats->per_bucket_packet_counter[i]);
    per_shard_flow_count.push_back(bess::utils::bucket_stats->per_bucket_flow_cache[i].size());
    pps += per_shard_pkt_rate[i];
    bess::utils::bucket_stats->per_bucket_packet_counter[i] = 0;
    bess::utils::bucket_stats->per_bucket_flow_cache[i].clear();
  }
  bess::utils::bucket_stats->bucket_table_lock.unlock();

  pps *= to_rate_per_sec;
  curr_packet_rate_ = (uint32_t)pps;

  std::map<uint16_t, uint16_t> moves =
      OnDemandLongTermOptimization(core_id, per_shard_pkt_rate, per_shard_flow_count);

  rte_atomic16_set(&curr_active_core_count_, active_core_count_);
  SendWorkerInfo();

  if (moves.size() && port_) {
    bess::ctrl::nfvctrl_bucket_mu.lock();
    bess::ctrl::trans_buckets = moves;
    bess::ctrl::nfvctrl_bucket_mu.unlock();

    port_->UpdateRssFlow(moves);
    LOG(INFO) << "on-demand; moves=" <<  moves.size() << ", cores=" << active_core_count_;
  }
  return moves.size();
}

void NFVCtrl::SendWorkerInfo() {
  int pktcnt = 2;

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
    eth->dst_addr = Ethernet::Address("b8:ce:f6:d2:3b:1a"); // CHECK HERE
    ip->src = be32_t(12345);
    ip->dst = monitor_dst_ip_;
    ip->length = be16_t(40);
    tcp->src_port = be16_t(uint16_t(worker_id_)); // whoami
    tcp->dst_port = be16_t(active_core_count_); // # of normal cores
    tcp->seq_num = be32_t(curr_packet_rate_);
    tcp->flags = Tcp::Flag::kSyn;

    tcp->checksum = CalculateIpv4TcpChecksum(*ip, *tcp);
    ip->checksum = CalculateIpv4Checksum(*ip);
    local_batch_->add(pkt);
  }

  // This is not robust. Do not send..
  // const queue_t qid = ACCESS_ONCE(qid_);
  // port_->SendPackets(qid, local_batch_->pkts(), pktcnt);
}
