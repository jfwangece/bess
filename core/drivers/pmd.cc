// Copyright (c) 2014-2016, The Regents of the University of California.
// Copyright (c) 2016-2017, Nefeli Networks, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the names of the copyright holders nor the names of their
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include "pmd.h"

#include <rte_bus_pci.h>

#include "../utils/ether.h"
#include "../utils/format.h"

#include <sys/syscall.h>
#include <sched.h>

namespace {
#define MIN_ZERO_POLL_COUNT 100
#define MIN_ZERO_POLL_PERIOD_US 50
#define gettid() syscall(SYS_gettid)

bool intr_on = false;
bool rt_on = false;
struct sched_param RT_HIGH_PRIORITY = { .sched_priority = 41, };

// pthread func: it synchronizes NIC's and CPU's clock.
void SyncClockInit(PMDPort *p) {
  p->SyncClock();
}

inline rte_flow* AddFlowRedirectRule(int port_id, int from, int to, int priority = 0) {
  struct rte_flow_attr attr;
  memset(&attr, 0, sizeof(struct rte_flow_attr));
  attr.ingress = 1;
  attr.group = from;
  attr.priority =  priority;

  struct rte_flow_action action[2];
  struct rte_flow_action_jump jump;
  jump.group = to;
  memset(action, 0, sizeof(struct rte_flow_action) * 2);
  action[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
  action[0].conf = &jump;
  action[1].type = RTE_FLOW_ACTION_TYPE_END;

  std::vector<rte_flow_item> pattern;
  rte_flow_item pat;
  pat.type = RTE_FLOW_ITEM_TYPE_ETH;
  pat.spec = 0;
  pat.mask = 0;
  pat.last = 0;
  pattern.push_back(pat);

  rte_flow_item end;
  memset(&end, 0, sizeof(struct rte_flow_item));
  end.type =  RTE_FLOW_ITEM_TYPE_END;
  pattern.push_back(end);

  struct rte_flow_error error;
  if (rte_flow_validate(port_id, &attr, pattern.data(), action, &error) == 0) {
    struct rte_flow *flow = rte_flow_create(port_id, &attr, pattern.data(), action, &error);
    return flow;
  }

  return nullptr;
}
} /// namespace

static const rte_eth_conf default_eth_conf(const rte_eth_dev_info &dev_info,
                                           int nb_rxq) {
  rte_eth_conf ret = {};

  ret.link_speeds = ETH_LINK_SPEED_AUTONEG;
  ret.rxmode.mq_mode = (nb_rxq > 1) ? ETH_MQ_RX_RSS : ETH_MQ_RX_NONE;
  ret.rxmode.offloads = 0;
  ret.rxmode.max_rx_pkt_len = 1514; // MTU + 14

  ret.rx_adv_conf.rss_conf = {
      .rss_key = nullptr,
      .rss_key_len = 0,
      .rss_hf = (ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP | ETH_RSS_SCTP) &
                dev_info.flow_type_rss_offloads,
  };

  return ret;
}

void PMDPort::UpdateRssReta() {
  int remapping_count = 1;
  for (size_t j = 0; j < reta_size_; j++) {
    reta_conf_[j / RTE_RETA_GROUP_SIZE].reta[j % RTE_RETA_GROUP_SIZE] = j % 5;
    reta_table_[j] = j%5;
  }

  if (remapping_count) {
    int ret = rte_eth_dev_rss_reta_update(dpdk_port_id_, reta_conf_, reta_size_);
    if (ret != 0) {
      LOG(ERROR) << "Failed to set NIC reta table: " << rte_strerror(ret);
    }
  }
}

void PMDPort::UpdateRssFlow() {
  if (AddFlowRedirectRule(dpdk_port_id_, 0, 1) != nullptr) {
    LOG(INFO) << "Group table rule supported";
  } else {
    LOG(INFO) << "No group table rule supported";
  }

  // Update the flow-rule in 2 steps
  // int tot = 1;
  // struct rte_flow_attr attr;
  // for (int i = 0; i < tot; i++) {
  //   memset(&attr, 0, sizeof(struct rte_flow_attr));
  //   attr.ingress = 1;
  //   struct rte_flow_action action[3];
  //   struct rte_flow_action_mark mark;
  //   struct rte_flow_action_rss rss;
  //   memset(action, 0, sizeof(action));
  //   memset(&rss, 0, sizeof(rss));
  // }
}

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

void PMDPort::TurnOnOffIntr(queue_t qid, bool on) {
  if (on) {
    rte_eth_dev_rx_intr_enable(dpdk_port_id_, qid);
  } else {
    rte_eth_dev_rx_intr_disable(dpdk_port_id_, qid);
  }
}

void PMDPort::SleepUntilRxInterrupt() {
  int num = 1;
  struct rte_epoll_event event[1];
  rte_epoll_wait(RTE_EPOLL_PER_THREAD, event, num, 1);
}

void PMDPort::InitDriver() {
  dpdk_port_t num_dpdk_ports = rte_eth_dev_count_avail();

  LOG(INFO) << static_cast<int>(num_dpdk_ports)
            << " DPDK PMD ports have been recognized:";

  for (dpdk_port_t i = 0; i < num_dpdk_ports; i++) {
    rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(i, &dev_info);

    bess::utils::Ethernet::Address lladdr;
    rte_eth_macaddr_get(i, reinterpret_cast<rte_ether_addr *>(lladdr.bytes));

    int numa_node = rte_eth_dev_socket_id(static_cast<int>(i));

    std::string pci_info;
    if (dev_info.device) {
      rte_bus *bus = rte_bus_find_by_device(dev_info.device);
      if (bus && !strcmp(bus->name, "pci")) {
        rte_pci_device *pci_dev = RTE_DEV_TO_PCI(dev_info.device);
        pci_info = bess::utils::Format(
            "%08x:%02hhx:%02hhx.%02hhx %04hx:%04hx  ", pci_dev->addr.domain,
            pci_dev->addr.bus, pci_dev->addr.devid, pci_dev->addr.function,
            pci_dev->id.vendor_id, pci_dev->id.device_id);
      }
    }

    LOG(INFO) << "DPDK port_id " << static_cast<int>(i) << " ("
              << dev_info.driver_name << ")   RXQ " << dev_info.max_rx_queues
              << " TXQ " << dev_info.max_tx_queues << "  " << lladdr.ToString()
              << "  " << pci_info << " numa_node " << numa_node;
  }
}

// Find a port attached to DPDK by its integral id.
// returns 0 and sets *ret_port_id to "port_id" if the port is valid and
// available.
// returns > 0 on error.
static CommandResponse find_dpdk_port_by_id(dpdk_port_t port_id,
                                            dpdk_port_t *ret_port_id) {
  if (port_id >= RTE_MAX_ETHPORTS) {
    return CommandFailure(EINVAL, "Invalid port id %d", port_id);
  }
  if (rte_eth_devices[port_id].state != RTE_ETH_DEV_ATTACHED) {
    return CommandFailure(ENODEV, "Port id %d is not available", port_id);
  }

  *ret_port_id = port_id;
  return CommandSuccess();
}

// Find a port attached to DPDK by its PCI address.
// returns 0 and sets *ret_port_id to the port_id of the port at PCI address
// "pci" if it is valid and available. *ret_hot_plugged is set to true if the
// device was attached to DPDK as a result of calling this function.
// returns > 0 on error.
static CommandResponse find_dpdk_port_by_pci_addr(const std::string &pci,
                                                  dpdk_port_t *ret_port_id,
                                                  bool *ret_hot_plugged) {
  dpdk_port_t port_id = DPDK_PORT_UNKNOWN;

  if (pci.length() == 0) {
    return CommandFailure(EINVAL, "No PCI address specified");
  }

  rte_pci_addr addr;
  if (rte_pci_addr_parse(pci.c_str(), &addr) != 0) {
    return CommandFailure(EINVAL,
                          "PCI address must be like "
                          "dddd:bb:dd.ff or bb:dd.ff");
  }

  const rte_bus *bus = nullptr;

  dpdk_port_t num_dpdk_ports = rte_eth_dev_count_avail();
  for (dpdk_port_t i = 0; i < num_dpdk_ports; i++) {
    rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(i, &dev_info);

    if (dev_info.device) {
      bus = rte_bus_find_by_device(dev_info.device);
      if (bus && !strcmp(bus->name, "pci")) {
        const rte_pci_device *pci_dev = RTE_DEV_TO_PCI(dev_info.device);
        if (rte_pci_addr_cmp(&addr, &pci_dev->addr) == 0) {
          port_id = i;
          break;
        }
      }
    }
  }

  // If still not found, maybe the device has not been attached yet
  if (port_id == DPDK_PORT_UNKNOWN) {
    int ret;
    char name[RTE_ETH_NAME_MAX_LEN];
    snprintf(name, RTE_ETH_NAME_MAX_LEN, "%08x:%02x:%02x.%02x", addr.domain,
             addr.bus, addr.devid, addr.function);

    ret = rte_eal_hotplug_add("pci", name, "");
    if (ret < 0) {
      return CommandFailure(ENODEV, "Cannot attach PCI device %s", name);
    }
    ret = rte_eth_dev_get_port_by_name(name, &port_id);
    if (ret < 0) {
      return CommandFailure(ENODEV, "Cannot find port id for PCI device %s",
                            name);
    }
    *ret_hot_plugged = true;
  }

  *ret_port_id = port_id;
  return CommandSuccess();
}

// Find a DPDK vdev by name.
// returns 0 and sets *ret_port_id to the port_id of "vdev" if it is valid and
// available. *ret_hot_plugged is set to true if the device was attached to
// DPDK as a result of calling this function.
// returns > 0 on error.
static CommandResponse find_dpdk_vdev(const std::string &vdev,
                                      dpdk_port_t *ret_port_id,
                                      bool *ret_hot_plugged) {
  dpdk_port_t port_id = DPDK_PORT_UNKNOWN;

  if (vdev.length() == 0) {
    return CommandFailure(EINVAL, "No vdev specified");
  }

  int ret = rte_dev_probe(vdev.c_str());
  if (ret < 0) {
    return CommandFailure(ENODEV, "Cannot attach vdev %s", vdev.c_str());
  }

  rte_dev_iterator iterator;
  RTE_ETH_FOREACH_MATCHING_DEV(port_id, vdev.c_str(), &iterator) {
    LOG(INFO) << "port id: " << port_id << "matches vdev: " << vdev;
    rte_eth_iterator_cleanup(&iterator);
    break;
  }

  *ret_hot_plugged = true;
  *ret_port_id = port_id;
  return CommandSuccess();
}

CommandResponse PMDPort::Init(const bess::pb::PMDPortArg &arg) {
  dpdk_port_t ret_port_id = DPDK_PORT_UNKNOWN;

  rte_eth_dev_info dev_info;
  rte_eth_conf eth_conf;
  rte_eth_rxconf eth_rxconf;

  int num_txq = num_queues[PACKET_DIR_OUT];
  int num_rxq = num_queues[PACKET_DIR_INC];

  int ret;

  CommandResponse err;
  switch (arg.port_case()) {
    case bess::pb::PMDPortArg::kPortId: {
      err = find_dpdk_port_by_id(arg.port_id(), &ret_port_id);
      break;
    }
    case bess::pb::PMDPortArg::kPci: {
      err = find_dpdk_port_by_pci_addr(arg.pci(), &ret_port_id, &hot_plugged_);
      break;
    }
    case bess::pb::PMDPortArg::kVdev: {
      err = find_dpdk_vdev(arg.vdev(), &ret_port_id, &hot_plugged_);
      break;
    }
    default:
      return CommandFailure(EINVAL, "No port specified");
  }

  if (err.error().code() != 0) {
    return err;
  }

  if (ret_port_id == DPDK_PORT_UNKNOWN) {
    return CommandFailure(ENOENT, "Port not found");
  }

  /* Use defaut rx/tx configuration as provided by PMD drivers,
   * with minor tweaks */
  rte_eth_dev_info_get(ret_port_id, &dev_info);

  eth_conf = default_eth_conf(dev_info, num_rxq);
  if (arg.loopback()) {
    eth_conf.lpbk_mode = 1;
  }

  timestamp_enabled_ = true;
  if (dev_info.rx_offload_capa & DEV_RX_OFFLOAD_TIMESTAMP) {
    if (timestamp_enabled_) {
      eth_conf.rxmode.offloads |= DEV_RX_OFFLOAD_TIMESTAMP;
      LOG(INFO) << "NIC: HW timestamp is supported and enabled";
    }
  } else {
    timestamp_enabled_ = false;
    LOG(INFO) << "NIC: HW timestamp is not supported";
  }

  lcore_rx_idle_count_ = 0;
  lcore_rx_idle_ts_ = 0;
  intr_enabled_ = false;
  rt_enabled_ = false;
  if (arg.enable_interrupt()) {
    intr_enabled_ = true;
    eth_conf.intr_conf.lsc = 1;
    eth_conf.intr_conf.rxq = 1;
  }
  if (arg.enable_rt()) {
    rt_enabled_ = true;
  }

  bench_rss_ = false;
  if (arg.bench_rss()) {
    bench_rss_ = true;
  }

  ret = rte_eth_dev_configure(ret_port_id, num_rxq, num_txq, &eth_conf);
  if (ret != 0) {
    return CommandFailure(-ret, "rte_eth_dev_configure() failed");
  }

  int sid = rte_eth_dev_socket_id(ret_port_id);
  if (sid < 0 || sid > RTE_MAX_NUMA_NODES) {
    sid = 0;  // if socket_id is invalid, set to 0
  }

  eth_rxconf = dev_info.default_rxconf;
  eth_rxconf.rx_drop_en = 1;

  if (dev_info.rx_desc_lim.nb_min > 0 &&
      queue_size[PACKET_DIR_INC] < dev_info.rx_desc_lim.nb_min) {
    int old_size_rxq = queue_size[PACKET_DIR_INC];
    queue_size[PACKET_DIR_INC] = dev_info.rx_desc_lim.nb_min;
    LOG(WARNING) << "resizing RX queue size from " << old_size_rxq << " to "
                 << queue_size[PACKET_DIR_INC];
  }

  if (dev_info.rx_desc_lim.nb_max > 0 &&
      queue_size[PACKET_DIR_INC] > dev_info.rx_desc_lim.nb_max) {
    int old_size_rxq = queue_size[PACKET_DIR_INC];
    queue_size[PACKET_DIR_INC] = dev_info.rx_desc_lim.nb_max;
    LOG(WARNING) << "capping RX queue size from " << old_size_rxq << " to "
                 << queue_size[PACKET_DIR_INC];
  }

  for (int i = 0; i < num_rxq; i++) {
    ret = rte_eth_rx_queue_setup(ret_port_id, i, queue_size[PACKET_DIR_INC],
                                 sid, &eth_rxconf,
                                 bess::PacketPool::GetDefaultPool(sid)->pool());
    if (ret != 0) {
      return CommandFailure(-ret, "rte_eth_rx_queue_setup() failed");
    }
  }

  if (dev_info.tx_desc_lim.nb_min > 0 &&
      queue_size[PACKET_DIR_OUT] < dev_info.tx_desc_lim.nb_min) {
    int old_size_txq = queue_size[PACKET_DIR_OUT];
    queue_size[PACKET_DIR_OUT] = dev_info.tx_desc_lim.nb_min;
    LOG(WARNING) << "resizing TX queue size from " << old_size_txq << " to "
                 << queue_size[PACKET_DIR_OUT];
  }

  if (dev_info.tx_desc_lim.nb_max > 0 &&
      queue_size[PACKET_DIR_OUT] > dev_info.tx_desc_lim.nb_max) {
    int old_size_txq = queue_size[PACKET_DIR_OUT];
    queue_size[PACKET_DIR_OUT] = dev_info.tx_desc_lim.nb_max;
    LOG(WARNING) << "capping TX queue size from " << old_size_txq << " to "
                 << queue_size[PACKET_DIR_OUT];
  }

  for (int i = 0; i < num_txq; i++) {
    ret = rte_eth_tx_queue_setup(ret_port_id, i, queue_size[PACKET_DIR_OUT],
                                 sid, nullptr);
    if (ret != 0) {
      return CommandFailure(-ret, "rte_eth_tx_queue_setup() failed");
    }
  }

  rte_eth_promiscuous_enable(ret_port_id);

  int offload_mask = 0;
  offload_mask |= arg.vlan_offload_rx_strip() ? ETH_VLAN_STRIP_OFFLOAD : 0;
  offload_mask |= arg.vlan_offload_rx_filter() ? ETH_VLAN_FILTER_OFFLOAD : 0;
  offload_mask |= arg.vlan_offload_rx_qinq() ? ETH_VLAN_EXTEND_OFFLOAD : 0;
  if (offload_mask) {
    ret = rte_eth_dev_set_vlan_offload(ret_port_id, offload_mask);
    if (ret != 0) {
      return CommandFailure(-ret, "rte_eth_dev_set_vlan_offload() failed");
    }
  }

  ret = rte_eth_dev_start(ret_port_id);
  if (ret != 0) {
    return CommandFailure(-ret, "rte_eth_dev_start() failed");
  }
  dpdk_port_id_ = ret_port_id;

  int numa_node = rte_eth_dev_socket_id(static_cast<int>(ret_port_id));
  node_placement_ =
      numa_node == -1 ? UNCONSTRAINED_SOCKET : (1ull << numa_node);

  rte_eth_macaddr_get(dpdk_port_id_,
                      reinterpret_cast<rte_ether_addr *>(conf_.mac_addr.bytes));

  // Reset hardware stat counters, as they may still contain previous data
  CollectStats(true);

  driver_ = dev_info.driver_name ?: "unknown";

  // Find the timestamp conversion equation
  if (timestamp_enabled_) {
    nic_port_id = dpdk_port_id_;

    uint64_t start, end;
    rte_eth_read_clock(dpdk_port_id_, &start);
    usleep(100000);  // 0.1 sec
    rte_eth_read_clock(dpdk_port_id_, &end);
    nic_tsc_hz = (end - start) * 10;

    linear_re_lock_.lock();
    system_shutdown_ = false;
    linear_re_lock_.unlock();
    std::thread(SyncClockInit, this).detach();
  }

  reta_size_ = dev_info.reta_size;
  memset(reta_conf_, 0, sizeof(reta_conf_));
  for (uint32_t i = 0; i < reta_size_; i++) {
    reta_conf_[i / RTE_RETA_GROUP_SIZE].mask = UINT64_MAX;
  }
  reta_table_ = new uint16_t(erta_size_);
  UpdateRssReta();

  // Run a set of NIC RSS benchmarks
  if (bench_rss_) {
    BenchUpdateRssReta();
  }

  int q_pkt_count = rte_eth_rx_queue_count(dpdk_port_id_, 0);
  if (q_pkt_count >= 0) {
    BenchRXQueueCount();
  } else {
    LOG(INFO) << "RX queue count func is not supported. Error code: " << q_pkt_count;
  }

  return CommandSuccess();
}

void PMDPort::SyncClock() {
  if (!timestamp_enabled_) {
    return;
  }

  // Set the sync clock thread to run on core 0
  cpu_set_t master_core;
  CPU_ZERO(&master_core);
  CPU_SET(0, &master_core);
  rte_thread_set_affinity(&master_core);

  uint64_t dat_x, dat_y;
  bool is_shutdown = false;
  while(1) {
    LinearRegression<uint64_t> linear_re;
    for (int i = 0; i < 8; i++) {
      rte_eth_read_clock(dpdk_port_id_, &dat_x);
      dat_y = rdtsc();
      linear_re.AddData(dat_x, dat_y);
      rte_delay_ms(100);
    }
    linear_re.Train();

    linear_re_lock_.lock();
    linear_re_ = linear_re;
    is_shutdown = system_shutdown_;
    linear_re_lock_.unlock();

    if (is_shutdown) {
      break;
    }

    rte_delay_ms(15000);
  }
}

void PMDPort::TestClock() {
  uint64_t dat_x, dat_y;
  if (timestamp_enabled_) {
    rte_eth_read_clock(dpdk_port_id_, &dat_x);
    dat_y = rdtsc();
    linear_re_lock_.lock_shared();
    LOG(INFO) << "NIC: " << linear_re_.GetY(dat_x) << ", CPU: " << dat_y << ", diff: " << dat_y - linear_re_.GetY(dat_x);
    LOG(INFO) << "Slope: " << linear_re_.GetSlope();
    linear_re_lock_.unlock_shared();
    }
}

CommandResponse PMDPort::UpdateConf(const Conf &conf) {
  CommandResponse resp = CommandSuccess();
  rte_eth_dev_stop(dpdk_port_id_);  // need to restart before return

  if (conf_.mtu != conf.mtu && conf.mtu != 0) {
    if (conf.mtu > SNBUF_DATA || conf.mtu < RTE_ETHER_MIN_MTU) {
      resp = CommandFailure(EINVAL, "mtu should be >= %d and <= %d",
                            RTE_ETHER_MIN_MTU, SNBUF_DATA);
      goto restart;
    }

    int ret = rte_eth_dev_set_mtu(dpdk_port_id_, conf.mtu);
    if (ret == 0) {
      conf_.mtu = conf.mtu;
    } else {
      resp = CommandFailure(-ret, "rte_eth_dev_set_mtu() failed");
      goto restart;
    }
  }

  if (conf_.mac_addr != conf.mac_addr && !conf.mac_addr.IsZero()) {
    rte_ether_addr tmp;
    rte_ether_addr_copy(
        reinterpret_cast<const rte_ether_addr *>(&conf.mac_addr.bytes), &tmp);
    int ret = rte_eth_dev_default_mac_addr_set(dpdk_port_id_, &tmp);
    if (ret == 0) {
      conf_.mac_addr = conf.mac_addr;
    } else {
      resp = CommandFailure(-ret, "rte_eth_dev_default_mac_addr_set() failed");
      goto restart;
    }
  }

restart:
  if (conf.admin_up) {
    int ret = rte_eth_dev_start(dpdk_port_id_);
    if (ret == 0) {
      conf_.admin_up = true;
    } else {
      return CommandFailure(-ret, "rte_eth_dev_start() failed");
    }
  }

  return resp;
}

void PMDPort::DeInit() {
  rte_eth_dev_stop(dpdk_port_id_);

  if (hot_plugged_) {
    rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(dpdk_port_id_, &dev_info);

    char name[RTE_ETH_NAME_MAX_LEN];
    int ret;

    if (dev_info.device) {
      rte_bus *bus = rte_bus_find_by_device(dev_info.device);
      if (rte_eth_dev_get_name_by_port(dpdk_port_id_, name) == 0) {
        rte_eth_dev_close(dpdk_port_id_);
        ret = rte_eal_hotplug_remove(bus->name, name);
        if (ret < 0) {
          LOG(WARNING) << "rte_eal_hotplug_remove("
                       << static_cast<int>(dpdk_port_id_)
                       << ") failed: " << rte_strerror(-ret);
        }
        return;
      } else {
        LOG(WARNING) << "rte_eth_dev_get_name failed for port"
                     << static_cast<int>(dpdk_port_id_);
      }
    } else {
      LOG(WARNING) << "rte_eth_def_info_get failed for port"
                   << static_cast<int>(dpdk_port_id_);
    }

    if (timestamp_enabled_) {
      linear_re_lock_.lock();
      system_shutdown_ = true;
      linear_re_lock_.unlock();
    }
    rte_eth_dev_close(dpdk_port_id_);
  }
}

void PMDPort::CollectStats(bool reset) {
  packet_dir_t dir;
  queue_t qid;

  if (reset) {
    rte_eth_stats_reset(dpdk_port_id_);
    return;
  }

  rte_eth_stats stats;
  int ret = rte_eth_stats_get(dpdk_port_id_, &stats);
  if (ret < 0) {
    LOG(ERROR) << "rte_eth_stats_get(" << static_cast<int>(dpdk_port_id_)
               << ") failed: " << rte_strerror(-ret);
    return;
  }

  VLOG(1) << bess::utils::Format(
      "PMD port %d: ipackets %" PRIu64 " opackets %" PRIu64 " ibytes %" PRIu64
      " obytes %" PRIu64 " imissed %" PRIu64 " ierrors %" PRIu64
      " oerrors %" PRIu64 " rx_nombuf %" PRIu64,
      dpdk_port_id_, stats.ipackets, stats.opackets, stats.ibytes, stats.obytes,
      stats.imissed, stats.ierrors, stats.oerrors, stats.rx_nombuf);

  port_stats_.inc.dropped = stats.imissed;

  // i40e/net_e1000_igb PMD drivers, ixgbevf and net_bonding vdevs don't support
  // per-queue stats
  if (driver_ == "net_i40e" || driver_ == "net_i40e_vf" ||
      driver_ == "net_ixgbe_vf" || driver_ == "net_bonding" ||
      driver_ == "net_e1000_igb") {
    // NOTE:
    // - if link is down, tx bytes won't increase
    // - if destination MAC address is incorrect, rx pkts won't increase
    port_stats_.inc.packets = stats.ipackets;
    port_stats_.inc.bytes = stats.ibytes;
    port_stats_.out.packets = stats.opackets;
    port_stats_.out.bytes = stats.obytes;
  } else {
    dir = PACKET_DIR_INC;
    for (qid = 0; qid < num_queues[dir]; qid++) {
      queue_stats[dir][qid].packets = stats.q_ipackets[qid];
      queue_stats[dir][qid].bytes = stats.q_ibytes[qid];
      queue_stats[dir][qid].dropped = stats.q_errors[qid];
    }

    dir = PACKET_DIR_OUT;
    for (qid = 0; qid < num_queues[dir]; qid++) {
      queue_stats[dir][qid].packets = stats.q_opackets[qid];
      queue_stats[dir][qid].bytes = stats.q_obytes[qid];
    }
  }
}

int PMDPort::RecvPackets(queue_t qid, bess::Packet **pkts, int cnt) {
  // Set the lcore thread to be RT thread
  if (unlikely(intr_enabled_ && !intr_on)) {
    // Enable interrupt
    uint32_t data = dpdk_port_id_ << CHAR_BIT | 0;
    int ret = rte_eth_dev_rx_intr_ctl_q(dpdk_port_id_, 0,
						RTE_EPOLL_PER_THREAD,
						RTE_INTR_EVENT_ADD,
						(void *)((uintptr_t)data));
    if (ret != 0) {
      intr_enabled_ = false;
      LOG(WARNING) << "Failed to enable interrupt for port " << dpdk_port_id_ << ". Error code " << ret;
    } else {
      intr_on = true;
    }
  }
  if (unlikely(rt_enabled_ && !rt_on)) {
    sched_setscheduler(gettid(), SCHED_FIFO, &RT_HIGH_PRIORITY);
    rt_on = true;
  }

start_rx:
  int recv = rte_eth_rx_burst(dpdk_port_id_, qid,
                              reinterpret_cast<rte_mbuf **>(pkts), cnt);
  if (!intr_enabled_) {
    return recv;
  }
  if (recv == 0) {    
    // lcore_rx_idle_count_ += 1;
    // if (lcore_rx_idle_count_ > MIN_ZERO_POLL_COUNT) {
    //   TurnOnOffIntr(qid, 1);
    //   SleepUntilRxInterrupt();
    //   TurnOnOffIntr(qid, 0);
    //   lcore_rx_idle_count_ = 0;
    //   goto start_rx;
    // }

    now_ = rdtsc();
    if (lcore_rx_idle_ts_ == 0) {
      lcore_rx_idle_ts_ = now_;
    } else {
      if (tsc_to_us(now_ - lcore_rx_idle_ts_) > MIN_ZERO_POLL_PERIOD_US) {
        TurnOnOffIntr(qid, 1);
        SleepUntilRxInterrupt();
        TurnOnOffIntr(qid, 0);
        lcore_rx_idle_ts_ = 0;
        goto start_rx;
      }
    }
  } else {
    lcore_rx_idle_count_ = 0;
    lcore_rx_idle_ts_ = 0;
  }

  return recv;
}

int PMDPort::SendPackets(queue_t qid, bess::Packet **pkts, int cnt) {
  int sent = rte_eth_tx_burst(dpdk_port_id_, qid,
                              reinterpret_cast<rte_mbuf **>(pkts), cnt);
  auto &stats = queue_stats[PACKET_DIR_OUT][qid];
  int dropped = cnt - sent;
  stats.dropped += dropped;
  stats.requested_hist[cnt]++;
  stats.actual_hist[sent]++;
  stats.diff_hist[dropped]++;
  return sent;
}

Port::LinkStatus PMDPort::GetLinkStatus() {
  rte_eth_link status;
  // rte_eth_link_get() may block up to 9 seconds, so use _nowait() variant.
  rte_eth_link_get_nowait(dpdk_port_id_, &status);

  return LinkStatus{.speed = status.link_speed,
                    .full_duplex = static_cast<bool>(status.link_duplex),
                    .autoneg = static_cast<bool>(status.link_autoneg),
                    .link_up = static_cast<bool>(status.link_status)};
}

ADD_DRIVER(PMDPort, "pmd_port", "DPDK poll mode driver")
