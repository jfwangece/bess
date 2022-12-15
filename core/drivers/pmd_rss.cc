#include "pmd.h"

#include <set>
#include <string>

namespace {
struct rte_flow_item ETH_ITEM = {
	RTE_FLOW_ITEM_TYPE_ETH,
  nullptr, nullptr, nullptr,
};
struct rte_flow_item IPV4_ITEM = {
	RTE_FLOW_ITEM_TYPE_IPV4,
	nullptr, nullptr, nullptr,
};
struct rte_flow_item END_ITEM = {
	RTE_FLOW_ITEM_TYPE_END,
	nullptr, nullptr, nullptr,
};

// Helper func for installing a flow redirection rule
inline rte_flow* AddFlowRedirectRule(int port_id, int from, int to, int priority = 0) {
  struct rte_flow_attr attr;
  memset((void*)&attr, 0, sizeof(struct rte_flow_attr));
  attr.ingress = 1;
  attr.group = from;
  attr.priority = priority;

  struct rte_flow_action_jump jump;
  memset((void*)&jump, 0, sizeof(struct rte_flow_action_jump));
  jump.group = to;

  struct rte_flow_action action[2];
  memset(action, 0, sizeof(struct rte_flow_action) * 2);
  action[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
  action[0].conf = &jump;
  action[1].type = RTE_FLOW_ACTION_TYPE_END;

  std::vector<rte_flow_item> pattern;
  pattern.push_back(ETH_ITEM);
  pattern.push_back(END_ITEM);

  struct rte_flow_error error;
  int ret = rte_flow_validate(port_id, &attr, pattern.data(), action, &error);
  if (ret == 0) {
    struct rte_flow *flow = rte_flow_create(port_id, &attr, pattern.data(), action, &error);
    return flow;
  } else {
    LOG(ERROR) << "Flow rule (redir) cannot be validated";
  }
  return nullptr;
}
} // namespace

void PMDPort::UpdateRssReta() {
  for (size_t j = 0; j < reta_size_; j++) {
    reta_table_[j] = 0;
    reta_conf_[j / RTE_RETA_GROUP_SIZE].reta[j % RTE_RETA_GROUP_SIZE] = 0;
  }

  int ret = rte_eth_dev_rss_reta_update(dpdk_port_id_, reta_conf_, reta_size_);
  if (ret != 0) {
    LOG(INFO) << "Failed to set NIC reta table: " << rte_strerror(ret);
  }
}

void PMDPort::UpdateRssReta(std::map<uint16_t, uint16_t>& moves) {
  // first = bucket ID; second = core ID;
  int remapping = 0;
  for (auto &it : moves) {
    if (reta_table_[it.first] != it.second) {
      remapping += 1;
    }
    reta_table_[it.first] = it.second;
    reta_conf_[it.first / RTE_RETA_GROUP_SIZE].reta[it.first % RTE_RETA_GROUP_SIZE] = it.second;
  }

  if (remapping) {
    int ret = rte_eth_dev_rss_reta_update(dpdk_port_id_, reta_conf_, reta_size_);
    if (ret != 0) {
      LOG(INFO) << "Failed to set NIC reta table: " << rte_strerror(ret);
    }
  }
}

void PMDPort::UpdateRssReta(std::map<uint16_t, uint16_t>& moves, uint16_t total_shards) {
  // first = shard ID; second = core ID;
  int remapping = 0;
  for (auto &it : moves) {
    uint16_t shard = it.first;
    uint16_t core_id = it.second;
    for (uint16_t reta_id = shard; reta_id < reta_size_; reta_id += total_shards) {
      if (reta_table_[reta_id] != core_id) {
        remapping += 1;
        reta_table_[reta_id] = core_id;
        reta_conf_[reta_id / RTE_RETA_GROUP_SIZE].reta[it.first % RTE_RETA_GROUP_SIZE] = core_id;
      }
    }
  }

  if (remapping) {
    int ret = rte_eth_dev_rss_reta_update(dpdk_port_id_, reta_conf_, reta_size_);
    if (ret != 0) {
      LOG(INFO) << "Failed to set NIC reta table: " << rte_strerror(ret);
    }
  }
}

void PMDPort::UpdateRssFlow() {
  if (!is_use_group_table_) {
    LOG(INFO) << "Group flow table is not supported";
    return;
  }

  struct rte_flow_attr attr;
  memset(&attr, 0, sizeof(struct rte_flow_attr));
  attr.ingress = 1;
  attr.group = 1 + (rte_flow_id_ % 2);

  struct rte_flow_action action[3];
  memset(action, 0, sizeof(struct rte_flow_action) * 3);

  int aid = 0;
  action[0].type = RTE_FLOW_ACTION_TYPE_MARK;
  struct rte_flow_action_mark mark;
  memset((void*)&mark, 0, sizeof(struct rte_flow_action_mark));
  mark.id = rte_flow_id_;
  action[0].conf = &mark;
  ++aid;

  action[aid].type = RTE_FLOW_ACTION_TYPE_RSS;
  struct rte_flow_action_rss rss;
  memset((void*)&rss, 0, sizeof(rss));
  rss.key = nullptr;
  rss.key_len = 0;
  rss.types = dpdk_port_conf_->rx_adv_conf.rss_conf.rss_hf;
  rss.queue_num = reta_size_;
  rss.queue = reta_table_.data();
  rss.level = 0;
  rss.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
  action[aid].conf = &rss;
  ++aid;

  std::string output;
  for (auto x : reta_table_) {
    output += std::to_string(x);
  }
  LOG(INFO) << output;

  action[aid].type = RTE_FLOW_ACTION_TYPE_END;
  ++aid;

  std::vector<rte_flow_item> pattern;
  pattern.push_back(ETH_ITEM);
  pattern.push_back(IPV4_ITEM);
  pattern.push_back(END_ITEM);

  struct rte_flow_error error;
  int ret = rte_flow_validate(dpdk_port_id_, &attr, pattern.data(), action, &error);
  if (ret == 0) {
    // Delete the previous RSS rule (i.e. 2-update ago)
    rte_flow* &prev = reta_flows_[1 + (rte_flow_id_ % 2)];
    if (prev != nullptr) {
      rte_flow_destroy(dpdk_port_id_, prev, &error);
    }
    struct rte_flow *flow = rte_flow_create(dpdk_port_id_, &attr, pattern.data(), action, &error);
    if (flow) {
      prev = flow;

      // Update the flow group redirection rule
      rte_flow* re_dir = AddFlowRedirectRule(
          dpdk_port_id_, 0,  1 + (rte_flow_id_ % 2), 1 + (rte_flow_id_ % 2));
      if (reta_flows_[0] != nullptr) {
        rte_flow_destroy(dpdk_port_id_, reta_flows_[0], &error);
      }
      reta_flows_[0] = re_dir;

      // Set the next flow RSS rule's ID
      rte_flow_id_ = (rte_flow_id_ + 1) % 2;
    }
  } else {
    LOG(ERROR) << "Flow rule (rss) cannot be validated. Error code: " << ret << "; msg: " << error.message;
  }
}

void PMDPort::UpdateRssFlow(std::map<uint16_t, uint16_t>& moves) {
  // first = bucket ID; second = core ID;
  int remapping = 0;
  for (auto &it : moves) {
    uint16_t reta_id = it.first;
    uint16_t core_id = it.second;
    if (reta_table_[reta_id] != core_id) {
      remapping += 1;
      reta_table_[reta_id] = core_id;
    }
  }

  if (remapping) {
    UpdateRssFlow();
  }
}

void PMDPort::UpdateRssFlow(std::map<uint16_t, uint16_t>& moves, uint16_t total_shards) {
  // first = shard ID; second = core ID;
  int remapping = 0;
  for (auto &it : moves) {
    uint16_t shard = it.first;
    uint16_t core_id = it.second;
    for (uint16_t reta_id = shard; reta_id < reta_size_; reta_id += total_shards) {
      if (reta_table_[reta_id] != core_id) {
        remapping += 1;
        reta_table_[reta_id] = core_id;
      }
    }
  }

  if (remapping) {
    UpdateRssFlow();
  }
}

// Performance benchmarks
void PMDPort::BenchUpdateRssReta() {
  uint64_t start, sum_cycle;

  // Reta update
  sum_cycle = 0;
  for (int i = 0; i < 3; i++) {
    start = rdtsc();
    UpdateRssReta();
    sum_cycle += rdtsc() - start;
    rte_delay_ms(500);
  }

  LOG(INFO) << "Bench rss: reta update";
  LOG(INFO) << " - reta table size: " << reta_size_;
  LOG(INFO) << " - update time: " << tsc_to_us(sum_cycle / 3) << " usec";

  // Flow update
  sum_cycle = 0;
  for (int i = 0; i < 3; i++) {
    start = rdtsc();
    UpdateRssFlow();
    sum_cycle += rdtsc() - start;
    rte_delay_ms(500);
  }

  LOG(INFO) << "Bench rss: flow table update";
  LOG(INFO) << " - update time: " << tsc_to_us(sum_cycle / 3) << " usec";
}

void PMDPort::BenchRXQueueCount() {
  uint64_t start, sum_cycle;

  sum_cycle = 0;
  for (int i = 0; i < 5; i++) {
    start = rdtsc();
    rte_eth_rx_queue_count(dpdk_port_id_, 0);
    sum_cycle += rdtsc() - start;
    rte_delay_ms(100);
  }

  LOG(INFO) << "Bench rx_queue_count:";
  LOG(INFO) << " - query time: " << tsc_to_us(sum_cycle / 5) << " usec";
}
