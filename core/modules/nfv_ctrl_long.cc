#include "nfv_ctrl.h"
#include "nfv_ctrl_msg.h"

#include "../utils/sys_measure.h"

// The amount of space to leave when packing buckets into CPUs
#define MIGRATE_HEAD_ROOM 0.1
#define ASSIGN_HEAD_ROOM 0.2

namespace {
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

std::map<uint16_t, uint16_t> NFVCtrl::FindMoves(std::vector<double>& per_cpu_pkt_rate,
                                                std::vector<uint16_t>& to_move_buckets,
                                                const std::vector<double>& per_bucket_pkt_rate) {
  std::map<uint16_t, uint16_t> moves;
  for (auto bucket : to_move_buckets) {
    double bucket_pkt_rate = per_bucket_pkt_rate[bucket];
    bool found = false;
    for (uint16_t i = 0; i < total_core_count_; i++) {
      if (bess::ctrl::core_state[i] &&
          per_cpu_pkt_rate[i] + bucket_pkt_rate < (flow_count_pps_threshold_[10000] * (1 - ASSIGN_HEAD_ROOM))) {
        per_cpu_pkt_rate[i] += bucket_pkt_rate;
        moves[bucket] = i;
        core_bucket_mapping_[i].push_back(bucket);
        found = true;
        break;
      }
    }

    // No core found. Need to add a new core
    if (!found) {
      for (uint16_t i = 0; i < total_core_count_; i++) {
        if (!bess::ctrl::core_state[i]) {
          per_cpu_pkt_rate[i] += bucket_pkt_rate;
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

std::map<uint16_t, uint16_t> NFVCtrl::LongTermOptimization(const std::vector<double>& per_bucket_pkt_rate) {
  // Compute the aggregated flow rate per core
  active_core_count_ = 0;
  std::vector<double> per_cpu_pkt_rate(total_core_count_);
  for (uint16_t i = 0; i < total_core_count_; i++) {
    per_cpu_pkt_rate[i] = 0;
    if (core_bucket_mapping_[i].size() > 0) {
      for (auto it : core_bucket_mapping_[i]) {
        per_cpu_pkt_rate[i] += per_bucket_pkt_rate[it];
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
    // Move a bucket and do this until the aggregated packet rate is below the threshold
    while (per_cpu_pkt_rate[i] > flow_count_pps_threshold_[10000] * (1 - MIGRATE_HEAD_ROOM) &&
          core_bucket_mapping_[i].size() > 0) {
      uint16_t bucket = core_bucket_mapping_[i].back();
      to_move_buckets.push_back(bucket);
      core_bucket_mapping_[i].pop_back();
      per_cpu_pkt_rate[i] -= per_bucket_pkt_rate[bucket];
      bess::ctrl::core_liveness[i] = 1;
    }
  }

  // For all buckets to be moved, assign them to a core
  std::map<uint16_t, uint16_t> moves = FindMoves(per_cpu_pkt_rate, to_move_buckets, per_bucket_pkt_rate);

  if (active_core_count_ == 1) {
    return moves;
  }

  // Find the CPU with minimum flow rate and delete it
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
      min_rate > flow_count_pps_threshold_[10000] / 2) {
    return moves;
  }

  // Move all buckets at the min-rate core; before that, save the current state
  per_cpu_pkt_rate[min_rate_core] = flow_count_pps_threshold_[10000];
  int org_active_cores = active_core_count_;
  std::vector<uint16_t> org_buckets = core_bucket_mapping_[min_rate_core];

  std::map<uint16_t, uint16_t> tmp_moves = FindMoves(per_cpu_pkt_rate, core_bucket_mapping_[min_rate_core], per_bucket_pkt_rate);

  if (active_core_count_ > org_active_cores ||
      tmp_moves.size() != org_buckets.size()) {
    // If this trial fails, undo all changes
    // - case 1: |FindMoves| uses more cores;
    // - case 2: |org_buckets| cannot be fit into normal cores;
    per_cpu_pkt_rate[min_rate_core] = min_rate;
    for (auto& m_it : tmp_moves) {
      core_bucket_mapping_[m_it.second].pop_back();
      per_cpu_pkt_rate[m_it.second] -= per_bucket_pkt_rate[m_it.first];
    }
  } else {
    core_bucket_mapping_[min_rate_core].clear();
    for (auto& m_it : tmp_moves) {
      moves[m_it.first] = m_it.second;
    }

    bess::ctrl::core_state[min_rate_core] = false;
    active_core_count_ -= 1;
  }

  return moves;
}

void NFVCtrl::UpdateFlowAssignment() {
  std::vector<double> per_bucket_pkt_rate;
  uint64_t c = 1000000000ULL / long_epoch_update_period_;

  bess::utils::bucket_stats->bucket_table_lock.lock();
  for (int i = 0; i < RETA_SIZE; i++) {
    per_bucket_pkt_rate.push_back(bess::utils::bucket_stats->per_bucket_packet_counter[i] * c);
    bess::utils::bucket_stats->per_bucket_packet_counter[i] = 0;
  }
  bess::utils::bucket_stats->bucket_table_lock.unlock();

  std::map<uint16_t, uint16_t> moves = LongTermOptimization(per_bucket_pkt_rate);
  if (moves.size()) {
    if (port_) {
      // port_->UpdateRssReta(moves);
      port_->UpdateRssFlow(moves);
    }
    LOG(INFO) << "(UpdateFlowAssignment) moves: " << moves.size();
  }
}
