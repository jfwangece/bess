#!/usr/bin/env python
import sys
import os
import io
import multiprocessing
import subprocess
import time
import threading
from bessctl import run_cli
from cloudlabutils import read_core_snapshot, slo_violation_analysis, get_short_term_profile

INIT_SERVER = False

# Global parameters
FILE_SERVER = "jfwang@68.181.32.207"
FILE_DIR = "/home/jfwang/ironside/large-files"
MLNX_OFED = "MLNX_OFED_LINUX-5.4-3.5.8.0-ubuntu18.04-x86_64.tgz"
BACKBONE_TRACE = "20190117-130000.tcp.pcap"
AS_TRACE  = "202209011400.tcp.pcap"
NF_CHAIN = "chain2"
# NF_CHAIN = "chain4"

LONG_PERIOD = 2000000000

## Server info
# Places to edit MACs
# * in cloud_pcap_relay.pcap: edit macs
# * in cloud_pcap_metron.pcap: edit macs
# * in nfv_ctrl_long.cc: edit traffic dst mac

# CLuster 1 (c6525-100g)
node_type = "c6525"
dev = "41:00.0"
all_ips = ["128.110.219.186", "128.110.219.159", "128.110.219.167", "128.110.219.184"]
all_macs = ["0c:42:a1:8c:db:fc", "0c:42:a1:8c:dc:94", "0c:42:a1:8c:dc:54", "0c:42:a1:8c:dc:24"]

# Cluster 2 (r6525)
# node_type = "r6525"
# dev = "81:00.0"
# all_ips = ["130.127.134.186", "130.127.134.159", "130.127.134.91", "130.127.134.94"]
# all_macs = ["b8:ce:f6:d2:3b:12", "b8:ce:f6:cc:8e:c4", "b8:ce:f6:cc:96:e4", "b8:ce:f6:cc:a2:c4"]

# The first server is used for traffic gen; other servers are used for workers
traffic_ip = all_ips[:1]
worker_ip = all_ips[1:]

## Helper functions
def wait_pids(pids):
    for p in pids:
        p.join()
    return

def wait_pids_with_timeout(pids, max_time=10):
    start = time.time()
    while time.time() - start < max_time:
        if any(p.poll() == None for p in pids):
            time.sleep(0.2)
            continue
        else:
            for p in pids:
                p.join()
                return

    for p in pids:
        p.terminate()
        p.join()
    return

def send_remote_file(ip, local_path, target_path):
    # print(local_path)
    local_path = os.path.abspath(local_path)
    remote_cmds = ['scp', local_path, 'uscnsl@{}:{}'.format(ip, target_path), '>/dev/null', '2>&1', '\n']
    p = subprocess.Popen(' '.join(remote_cmds), shell=True,
                        universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    timer = threading.Timer(5, p.kill)
    try:
        timer.start()
        out, err = p.communicate()
        if len(out) > 0:
            print(out)
        if len(err) > 0:
            print(err)
    finally:
        timer.cancel()
    return

def run_remote_command(ip, cmd):
    # ssh uscnsl@130.127.134.91 "/local/bess/bessctl/bessctl \"run nfvctrl/cloud_chain4 TRAFFIC_MAC='b8:ce:f6:d2:3b:12',BESS_WID=1,BESS_SLO=200000,BESS_SPROFILE='/local/bess/short.prof',BESS_LPROFILE='/local/bess/long.prof'\""
    remote_cmd = ['ssh', 'uscnsl@{}'.format(ip), '"{}"'.format(cmd), '>/dev/null', '2>&1', '\n']
    os.system(' '.join(remote_cmd))
    return

def run_remote_command_with_output(ip, cmd):
    remote_cmd = ['ssh', 'uscnsl@{}'.format(ip), '"{}"'.format(cmd), '\n']
    os.system(' '.join(remote_cmd))
    return

def run_remote_besscmd(ip, cmds):
    cmds_str = u' '.join(cmds)
    remote_cmds = ['./bessctl/bessctl.py', ip, cmds_str, '\n']
    p = subprocess.Popen(remote_cmds, universal_newlines=True,
                        stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p

## Basic utility functions
def get_mac_from_server(ip):
    cmd = "ifconfig | grep 10.10 -A 2 | grep eth"
    run_remote_command_with_output(ip, cmd)
    return

def reset_grub(ip):
    print("Reset grub conf for {}".format(ip))

    cmd = "git clone https://github.com/jwangee/FaaS-Setup.git"
    run_remote_command(ip, cmd)

    if node_type == "c6525":
        cmd = "cd ./FaaS-Setup && git pull && ./ironside-update-grub.sh"
        run_remote_command(ip, cmd)
    if node_type == "r6525":
        cmd = "cd ./FaaS-Setup && git pull && ./ironside-update-grub.sh"
        run_remote_command(ip, cmd)
    return

def install_mlnx(ip):
    print("Install MLNX OFED for {}".format(ip))

    cmd = "sudo apt update -y"
    run_remote_command(ip, cmd)
    cmd = "sudo apt install -y htop git"
    run_remote_command(ip, cmd)
    cmd = "git clone https://github.com/jwangee/FaaS-Setup.git"
    run_remote_command(ip, cmd)

    # Download MLNX OFED
    cmd = "scp {}:{}/{} /local".format(FILE_SERVER, FILE_DIR, MLNX_OFED)
    run_remote_command(ip, cmd)
    cmd = "cd ./FaaS-Setup && git pull && ./mlnx-ofed-install.sh"
    run_remote_command(ip, cmd)
    return

def install_bess(recompile, ip):
    print("Install BESS daemon for {}".format(ip))

    if recompile:
        cmd = "sudo rm -rf /tmp/bess*"
        run_remote_command(ip, cmd)
        cmd = "sudo pkill -f bessd"
        run_remote_command(ip, cmd)
        cmd = "sudo pkill -f solver"
        run_remote_command(ip, cmd)
        cmd = "sudo apt install -y htop git && git clone https://github.com/jwangee/FaaS-Setup.git"
        run_remote_command(ip, cmd)
        cmd = "cd ./FaaS-Setup && git pull && ./ironside-install.sh"
        run_remote_command(ip, cmd)
    else:
        cmd = "cd /local/bess && git pull"
        run_remote_command(ip, cmd)
    return

def setup_cpu_memory(ip):
    print("Setup hyperthread for {}".format(ip))
    cmd = "git clone https://github.com/jwangee/FaaS-Setup.git"
    run_remote_command(ip, cmd)
    cmd = "cd ./FaaS-Setup && git pull && ./ironside-hyperthread.sh"
    run_remote_command(ip, cmd)

    print("Setup hugepages for {}".format(ip))
    cmd1 = "echo 8 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages"
    run_remote_command(ip, cmd1)
    cmd2 = "echo 8 | sudo tee /sys/devices/system/node/node1/hugepages/hugepages-1048576kB/nr_hugepages"
    run_remote_command(ip, cmd2)
    return

def start_remote_bessd(ip, runtime="bess"):
    # kill the old one
    cmd = "sudo pkill -9 -f bessd"
    run_remote_command(ip, cmd)
    # start the new one
    bessd = "/local/bess/core/bessd"
    bessd_cmd = "sudo {} --dpdk=true --buffers=1048576 -k".format(bessd)
    run_remote_command(ip, bessd_cmd)
    return

def start_traffic_ironside_ingress(tip, num_worker, mode, pkt_thresh=2500000):
    """ Start a traffic generator with the worker-level load balancing scheme
    (such as Ironside's ingress).
    """
    cmds = ["run", "nfvctrl/cloud_pcap_replay_mc",
            "BESS_NUM_WORKER={}, BESS_IG={}, BESS_PKT_RATE_THRESH={}".format(num_worker, mode, pkt_thresh)]
    # cmds = ["run", "nfvctrl/cloud_pcap_replay", "BESS_NUM_WORKER={}, BESS_IG={}".format(num_worker, mode)]

    ## rpc method
    # p = run_remote_besscmd(tip, cmds)
    # out, err = p.communicate()
    # if len(out) > 0:
    #     print(out)

    ## ssh method
    x = ' '.join(cmds)
    run_bess_cmd = r'/local/bess/bessctl/bessctl \"{}\"'.format(x)
    run_remote_command(tip, run_bess_cmd)
    print("traffic {} starts: worker-scale routing".format(tip))

# run nfvctrl/cloud_pcap_metron BESS_NUM_WORKER=3, BESS_IG=0, BESS_SLO=100000
def start_traffic_metron_ingress(tip, num_worker, mode, slo=100000):
    """ Start a traffic generator with the core-level load balancing scheme
    (such as Metron's and Quadrant's ingress).
    |mode|: 0 for Metron; 1 for Quadrant;
    """
    pkt_thresh = 900000
    cmds = ["run", "nfvctrl/cloud_pcap_metron",
            "BESS_NUM_WORKER={}, BESS_IG={}, BESS_PKT_RATE_THRESH={}, BESS_SLO={}".format(num_worker, mode, pkt_thresh, slo)]
    x = ' '.join(cmds)
    run_bess_cmd = r'/local/bess/bessctl/bessctl \"{}\"'.format(x)
    run_remote_command(tip, run_bess_cmd)
    print("traffic {} starts: core-scale routing (metron)".format(tip))

def start_traffic_quadrant_ingress(tip, num_worker, mode, slo=100000):
    """ Start a traffic generator with the core-level load balancing scheme
    (such as Metron's and Quadrant's ingress).
    |mode|: 0 for Metron; 1 for Quadrant;
    """
    pkt_thresh = 1200000
    cmds = ["run", "nfvctrl/cloud_pcap_metron",
            "BESS_NUM_WORKER={}, BESS_IG={}, BESS_PKT_RATE_THRESH={}, BESS_SLO={}".format(num_worker, mode, pkt_thresh, slo)]
    x = ' '.join(cmds)
    run_bess_cmd = r'/local/bess/bessctl/bessctl \"{}\"'.format(x)
    run_remote_command(tip, run_bess_cmd)
    print("traffic {} starts: core-scale routing (quadrant)".format(tip))

def start_flowgen(tip, flow, rate):
    cmds = ["run", "nfvctrl/cloud_flowgen BESS_FLOW={}, BESS_PKT_RATE={}".format(flow, rate)]
    x = ' '.join(cmds)
    run_bess_cmd = r'/local/bess/bessctl/bessctl \"{}\"'.format(x)
    run_remote_command(tip, run_bess_cmd)
    print("flowgen {} starts".format(tip))

# For short-term profiling, set |exp_id| to be 1.
def start_ironside_worker(wip, worker_id, slo, short, long, exp_id=0):
    remote_short = "/local/bess/short.prof"
    remote_long = "/local/bess/long.prof"
    send_remote_file(wip, short, remote_short)
    send_remote_file(wip, long, remote_long)
    print("ironside worker {} gets short-term and long-term profiles (slo={} us)".format(worker_id, slo))

    cmds = ["run", "nfvctrl/cloud_{}".format(NF_CHAIN)]
    extra_cmds = ["TRAFFIC_MAC='{}'".format(all_macs[0]),
            "BESS_WID={}".format(worker_id),
            "BESS_SLO={}".format(slo),
            "BESS_SPROFILE='{}'".format(remote_short),
            "BESS_LPROFILE='{}'".format(remote_long),
            "BESS_LPERIOD={}".format(LONG_PERIOD)]
    if exp_id == 1 or exp_id == 2:
        # Profiling mode
        extra_cmds.append("BESS_EXP_ID={}".format(exp_id))
    cmds.append(", ".join(extra_cmds))
    x = ' '.join(cmds)
    run_bess_cmd = r'/local/bess/bessctl/bessctl \"{}\"'.format(x)
    run_remote_command(wip, run_bess_cmd)
    print("ironside worker {} starts: {}".format(wip, NF_CHAIN))

def start_dummy_worker(wip):
    cmds = ["run", "nfvctrl/cloud_dummy"]
    extra_cmd = "TRAFFIC_MAC='{}'".format(all_macs[0])
    cmds.append(extra_cmd)
    x = ' '.join(cmds)
    run_bess_cmd = r'/local/bess/bessctl/bessctl \"{}\"'.format(x)
    run_remote_command(wip, run_bess_cmd)
    print("ironside (dummy) worker {} starts: dummy chain".format(wip))

def start_metron_worker(wip, worker_id):
    cmds = ["run", "nfvctrl/cloud_metron_{}".format(NF_CHAIN)]
    extra_cmd = "BESS_EXP_ID=2, BESS_SWITCH_CORE=1, BESS_WORKER_CORE=18, TRAFFIC_MAC='{}', BESS_WID={}".format(all_macs[0], worker_id)
    cmds.append(extra_cmd)
    x = ' '.join(cmds)
    run_bess_cmd = r'/local/bess/bessctl/bessctl \"{}\"'.format(x)
    run_remote_command(wip, run_bess_cmd)
    print("metron worker {} starts: {}".format(wip, NF_CHAIN))

def start_quadrant_worker(wip, worker_id):
    cmds = ["run", "nfvctrl/cloud_metron_{}".format(NF_CHAIN)]
    extra_cmd = "BESS_EXP_ID=3, BESS_SWITCH_CORE=1, BESS_WORKER_CORE=18, TRAFFIC_MAC='{}', BESS_WID={}".format(all_macs[0], worker_id)
    cmds.append(extra_cmd)
    x = ' '.join(cmds)
    run_bess_cmd = r'/local/bess/bessctl/bessctl \"{}\"'.format(x)
    run_remote_command(wip, run_bess_cmd)
    print("quadrant worker {} starts {}".format(wip, NF_CHAIN))

def start_dyssect_worker(wip, worker_id, slo):
    cmd = "sudo pkill -f bessd"
    run_remote_command(wip, cmd)
    cmd = "sudo pkill -f solver"
    run_remote_command(wip, cmd)

    bessd = "/users/uscnsl/bess/core/bessd"
    bessd_cmd = "sudo {} --dpdk=true --buffers=1048576 -k".format(bessd)
    run_remote_command(wip, bessd_cmd)

    cmd = "/users/uscnsl/bess/solver 1>/dev/null 2>/dev/null &"
    run_remote_command_with_output(wip, cmd)

    cmds = ["run", "nfvctrl/cloud_dyssect_chain4",
            "CONTROLLER_CORE=28," "SHARDS=64,", "BESS_SLO={},".format(slo), "INPUT_PARA=10000,"]
    extra_cmd = ' '.join(cmds)
    cmd = "/users/uscnsl/bess/bessctl/bessctl {}".format(extra_cmd)
    run_remote_command(wip, cmd)
    print("dyssect worker {} starts".format(wip))

def parse_latency_result(tip):
    cmds = ['command', 'module', 'measure0', 'get_summary', 'MeasureCommandGetSummaryArg', '{"latency_percentiles": [50.0, 90.0, 95.0, 98.0, 99.0]}']
    p = run_remote_besscmd(tip, cmds)
    out, err = p.communicate()
    # print(out + "\n")
    fields = []
    lines = out.split('\n')
    for line in lines:
        # percentile_values_ns: 187300
        if 'packets' in line:
            fields.append(int(line.split(':')[1].strip()))
        if 'percentile_values_ns' in line:
            fields.append(float(line.split(':')[1].strip()) / 1000.0)
    return fields

# For CPU core usage
def parse_cpu_time_result(wip, runtime='nfv_core0'):
    if runtime == "dyssect":
        cmds = ["ssh", "uscnsl@{}".format(wip), "cat", "/users/uscnsl/dyssect_usage.dat"]
        p = subprocess.Popen(cmds, universal_newlines=True,
                        stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        return int(out)
    else:
        cmds = ['command', 'module', runtime, 'get_core_time', 'EmptyArg']
        p = run_remote_besscmd(wip, cmds)
        out, err = p.communicate()
        lines = out.split('\n')
        for line in lines:
            if 'core_time' in line:
                return int(line.split(':')[2].strip())
    return 0

# For short-term profiling
def parse_cpu_epoch_result(wip):
    cmds = ['command', 'module', 'nfvctrl', 'get_summary', 'EmptyArg']
    p = run_remote_besscmd(wip, cmds)
    out, err = p.communicate()
    time.sleep(1)

    for core_id in range(5):
        remote_path = "/users/uscnsl/stats{}.txt".format(core_id)
        local_path = "/tmp/stat{}.txt".format(core_id)
        remote_cmd = ['scp', 'uscnsl@{}:{}'.format(wip, remote_path), local_path, '>/dev/null', '2>&1', '\n']
        os.system(' '.join(remote_cmd))

    for core_id in range(5):
        local_path = "/tmp/stat{}.txt".format(core_id)
        fp = open(local_path, "r")
        lines = fp.readlines()
        fp.close()
        if len(lines) < 100:
            continue
        else:
            core_snapshots = read_core_snapshot(local_path)
            slo_vio_nodes, non_slo_vio_nodes = slo_violation_analysis(core_snapshots)
            if len(slo_vio_nodes) > 0:
                short_profile = get_short_term_profile(slo_vio_nodes)
                return short_profile
    return 0


## Running utility functions in a loop
def get_macs_for_all():
    # Run remote commands one at a time.
    ips = traffic_ip + worker_ip
    for ip in ips:
        get_mac_from_server(ip)
    print("Done getting MACs")
    return

def reset_grub_for_all():
    # reset grub configuration
    pids = []
    for ip in all_ips:
        p = multiprocessing.Process(target=reset_grub, args=(ip,))
        p.start()
        pids.append(p)
    wait_pids(pids)

    print("Done resetting grub")
    return

def install_mlnx_for_all():
    # install mlnx ofed
    pids = []
    for ip in all_ips:
        p = multiprocessing.Process(target=install_mlnx, args=(ip,))
        p.start()
        pids.append(p)
    wait_pids(pids)

    print("Done installing mlnx")
    return

def install_bess_for_all():
    # install ironside bessd
    pids = []
    for ip in all_ips:
        p = multiprocessing.Process(target=install_bess, args=(True, ip,))
        p.start()
        pids.append(p)
    wait_pids(pids)

    print("Done installing ironside")
    return

def fetch_bess_for_all():
    # install ironside bessd
    pids = []
    for ip in all_ips:
        p = multiprocessing.Process(target=install_bess, args=(False, ip,))
        p.start()
        pids.append(p)
    wait_pids(pids)

    print("Done fetching ironside configures")
    return

def fetch_traffic_trace(ip):
    ## Download all traffic traces used in the evaluation
    # Backbone
    cmd = "scp {}:{}/{} /local/bess/experiment_conf".format(FILE_SERVER, FILE_DIR, BACKBONE_TRACE)
    run_remote_command(ip, cmd)

    # AS
    # cmd = "scp {}:{}/{} /local/bess/experiment_conf".format(FILE_SERVER, FILE_DIR, AS_TRACE)
    # run_remote_command(ip, cmd)

    print("Done fetching traffic traces")
    return

def setup_cpu_hugepage_for_all():
    # hugepage all servers
    pids = []
    for ip in all_ips:
        p = multiprocessing.Process(target=setup_cpu_memory, args=(ip,))
        p.start()
        pids.append(p)
    wait_pids(pids)

    print("exp: all hugepages ready")
    return

def run_traffic():
    pids = []
    for tip in traffic_ip:
        p = multiprocessing.Process(target=start_remote_bessd, args=(tip,))
        p.start()
        pids.append(p)
    wait_pids(pids)

    for tip in traffic_ip:
        start_traffic_ironside_ingress(tip)
    print("exp: traffic started")

    time.sleep(30)

    delay = parse_latency_result(traffic_ip[0])
    print("delay (in us): {}".format(delay))

    print("exp: done")
    return delay

### Short-term and long-term profiles
## Profile helper
def long_term_profile_once(slo, flow, pkt_rate):
    selected_worker_ips = [worker_ip[0]]
    exp_duration = 15

    # Start all bessd
    pids = []
    for tip in traffic_ip:
        p = multiprocessing.Process(target=start_remote_bessd, args=(tip,))
        p.start()
        pids.append(p)
    for wip in worker_ip:
        p = multiprocessing.Process(target=start_remote_bessd, args=(wip,))
        p.start()
        pids.append(p)
    wait_pids(pids)
    print("exp: all bessd started")

    # Run all workers
    short_profile = "./nf_profiles/short_term_base.pro"
    long_profile = "./nf_profiles/long_term_base.pro"
    pids = []
    for i, wip in enumerate(selected_worker_ips):
        p = multiprocessing.Process(target=start_ironside_worker, args=(wip, i, slo, short_profile, long_profile, 1))
        p.start()
        pids.append(p)
    wait_pids(pids)
    print("exp: all workers started")

    total_flow = flow
    total_pkt_rate = pkt_rate
    for tip in traffic_ip:
        start_flowgen(tip, total_flow, total_pkt_rate)
    print("exp: traffic started")

    time.sleep(exp_duration)

    measure_results = parse_latency_result(traffic_ip[0])
    if len(measure_results) == 0:
        print("------------------------------------------")
        print("- Ironside short-term profile: no result -")
        print("------------------------------------------")
        return

    total_packets = measure_results[0]
    delay = measure_results[1:]
    core_usage = []
    for i, wip in enumerate(selected_worker_ips):
        core_usage.append(parse_cpu_time_result(wip) / 1000)
    avg_core_usage = sum(core_usage) / 1000000.0 / exp_duration

    print("---------------------------------------------------------------")
    print("- Ironside worker-scale profile result")
    print("- flowgen: flows={}, rate={}".format(flow, pkt_rate))
    print("- total packets: {}".format(total_packets))
    print("- pkt delay (in us): {}".format(delay))
    print("- core usage (in us): {}".format(core_usage))
    print("- core usage sum (in us): {}".format(sum(core_usage)))
    print("- avg core usage: {}".format(avg_core_usage))
    print("---------------------------------------------------------------")
    return (delay[0], delay[1])

# Profile an NF chain's single-core performance in a cross-machine setting.
# The input determines the target latency SLO and traffic input metrics.
# |flow_range|: a list of active flow counts to profile.
# |rate_range|: a list of packet rates to profile.
def run_long_term_profile(slo, flow_range, rate_range):
    start_time = time.time()

    slo_us = int(slo / 1000)
    nf_profile_p50 = {}
    nf_profile_p90 = {}
    for f in sorted(flow_range):
        left, right = 0, len(rate_range) - 1
        while left <= right:
            mid = (left + right) // 2
            delay = long_term_profile_once(slo, f, rate_range[mid])
            if delay[0] <= slo_us:
                left = mid + 1
            else:
                right = mid - 1

        target_idx = left - 1
        if target_idx == -1:
            raise Exception("The min rate cannot meet the target slo")
        else:
            nf_profile_p50[f] = rate_range[target_idx]

        # for r in sorted(rate_range):
        #     if delay==None or len(delay) == 0:
        #         continue
        #     if delay[1] * 1000 <= slo:
        #         nf_profile_p90[f] = r
        #     if delay[0] * 1000 <= slo:
        #         nf_profile_p50[f] = r
        #     else:
        #         # early break for saving time (|slo| is in ns)
        #         break

    if len(nf_profile_p50) > 0:
        fp1 = open("./long_{}_p50.pro".format(slo_us), "w+")
        keys = sorted(nf_profile_p50.keys())
        for key in keys:
            if key not in nf_profile_p50:
                continue
            val = nf_profile_p50[key]
            fp1.write("{} {}\n".format(key ,val))
        fp1.close()

    if len(nf_profile_p90) > 0:
        fp2 = open("./long_{}_p90.pro".format(slo_us), "w+")
        keys = sorted(nf_profile_p90.keys())
        for key in keys:
            if key not in nf_profile_p90:
                continue
            val = nf_profile_p90[key]
            fp2.write("{} {}\n".format(key ,val))
        fp2.close()

    print("Finish long-term profile under SLO = {} us", slo_us)

    end_time = time.time()
    diff = int(end_time - start_time)
    print("Total profiling time: {} minutes, {} seconds".format(diff / 60, diff % 60))
    return

def run_long_profile_under_slos():
    if NF_CHAIN == "chain2":
        target_slos = range(200000, 700000, 100000) # 100-600 us
        flow_range = range(500, 6500, 500)
        rate_range = range(500000, 800000, 20000)
    if NF_CHAIN == "chain4":
        target_slos = range(100000, 700000, 100000) # 100-600 us
        flow_range = range(500, 6500, 500)
        rate_range = range(1800000, 2200000, 20000)

    # Run!
    for slo in target_slos:
        run_long_term_profile(slo, flow_range, rate_range)
    return

## Short-term profile
# |slo| is the target latency SLO (in ns).
def short_term_profile_once(slo):
    num_worker = 1
    selected_worker_ips = worker_ip[:num_worker]
    exp_duration = 15
    slo_us = int(slo / 1000)

    # Start all bessd
    pids = []
    for tip in traffic_ip:
        p = multiprocessing.Process(target=start_remote_bessd, args=(tip,))
        p.start()
        pids.append(p)
    for i, wip in enumerate(selected_worker_ips):
        p = multiprocessing.Process(target=start_remote_bessd, args=(wip,))
        p.start()
        pids.append(p)
    wait_pids(pids)
    print("exp: all bessd started")

    # Run all workers
    pids = []
    short_profile = "./nf_profiles/short_term_base.pro"
    long_profile = "./nf_profiles/{}/long_{}_p50.pro".format(NF_CHAIN, slo_us)
    for i, wip in enumerate(selected_worker_ips):
        p = multiprocessing.Process(target=start_ironside_worker, args=(wip, i, slo, short_profile, long_profile, 2))
        p.start()
        pids.append(p)
    wait_pids(pids)
    print("exp: all workers started")

    ig_mode_text = ["min core", "min traffic", "max core", "max traffic"]
    ig_mode = 3
    for tip in traffic_ip:
        start_traffic_ironside_ingress(tip, num_worker, ig_mode)
    print("exp: traffic started")

    time.sleep(exp_duration)

    measure_results = parse_latency_result(traffic_ip[0])
    if len(measure_results) == 0:
        print("------------------------------------------")
        print("- Ironside short-term profile: no result -")
        print("------------------------------------------")
        return
    short_profile = parse_cpu_epoch_result(worker_ip[0])

    total_packets = measure_results[0]
    delay = measure_results[1:]
    core_usage = []
    for i, wip in enumerate(selected_worker_ips):
        core_usage.append(parse_cpu_time_result(wip) / 1000)
    avg_core_usage = sum(core_usage) / 1000000.0 / (exp_duration)

    print("---------------------------------------------------------------")
    print("- Ironside short-term profile result -")
    print("- total packets: {}".format(total_packets))
    print("- pkt delay (in us): {}".format(delay))
    print("- core usage (in us): {}".format(core_usage))
    print("- avg core usage: {}".format(avg_core_usage))
    print("---------------------------------------------------------------")
    return short_profile

def run_short_term_profile(slo):
    short_profile = short_term_profile_once(slo)

    # write |short_profile| to a local file
    slo_us = slo / 1000
    fp = open("./short_{}.pro".format(slo_us), "w+")
    for flow_count, pkt_count in short_profile:
        fp.write("{} {}\n".format(flow_count, pkt_count))
    fp.close()
    return

def run_short_profile_under_slos():
    target_slos = [100000, 200000, 300000, 400000, 500000, 600000]

    for slo in target_slos:
        run_short_term_profile(slo)
    return

### Ironside experiments
## Single-worker experiment
def run_worker_exp(slo):
    exp_duration = 50
    selected_worker_ips = [worker_ip[0]]

    # Start all bessd
    pids = []
    for tip in traffic_ip:
        p = multiprocessing.Process(target=start_remote_bessd, args=(tip,))
        p.start()
        pids.append(p)
    for wip in worker_ip:
        p = multiprocessing.Process(target=start_remote_bessd, args=(wip,))
        p.start()
        pids.append(p)
    wait_pids(pids)
    print("exp: all bessd started")

    # Run all workers
    short_profile = "./nf_profiles/short_term_base.pro"
    long_profile = "./nf_profiles/long_term_base.pro"
    pids = []
    for i, wip in enumerate(selected_worker_ips):
        p = multiprocessing.Process(target=start_ironside_worker, args=(wip, i, slo, short_profile, long_profile))
        p.start()
        pids.append(p)
    wait_pids(pids)
    print("exp: all workers started")

    flow = 1000
    pkt_rate = 100000
    for tip in traffic_ip:
        start_flowgen(tip, flow, pkt_rate)
    print("exp: traffic started")

    time.sleep(exp_duration)

    measure_results = parse_latency_result(traffic_ip[0])
    if len(measure_results) == 0:
        print("- Ironside rack-scale exp: no result - ")
        return

    total_packets = measure_results[0]
    delay = measure_results[1:]
    core_usage = []
    for i, wip in enumerate(selected_worker_ips):
        core_usage.append(parse_cpu_time_result(wip) / 1000)
    avg_core_usage = sum(core_usage) / 1000000.0 / exp_duration

    print("---------------------------------------------------------------")
    print("- Ironside worker-scale exp result")
    print("- flowgen: flows={}, rate={}".format(flow, pkt_rate))
    print("- total packets: {}".format(total_packets))
    print("- pkt delay (in us): {}".format(delay))
    print("- core usage (in us): {}".format(core_usage))
    print("- core usage sum (in us): {}".format(sum(core_usage)))
    print("- avg core usage: {}".format(avg_core_usage))
    print("---------------------------------------------------------------")
    return (delay[0], delay[1])

## Rack-scale experiments
# run nfvctrl/cloud_pcap_replay BESS_NUM_WORKER=4, BESS_IG=3
# run nfvctrl/cloud_pcap_replay_mc BESS_NUM_WORKER=4, BESS_IG=3, BESS_PKT_RATE_THRESH=3000000
# run nfvctrl/cloud_chain4 BESS_SPROFILE="./short.prof", BESS_LPROFILE="./long.prof", TRAFFIC_MAC="b8:ce:f6:d2:3b:12"
def run_cluster_exp(num_worker, slo, short_profile, long_profile):
    exp_duration = 50
    selected_worker_ips = []
    for i in range(num_worker):
        selected_worker_ips.append(worker_ip[i])

    # Start all bessd
    pids = []
    for tip in traffic_ip:
        p = multiprocessing.Process(target=start_remote_bessd, args=(tip,))
        p.start()
        pids.append(p)
    for wip in worker_ip:
        p = multiprocessing.Process(target=start_remote_bessd, args=(wip,))
        p.start()
        pids.append(p)
    wait_pids(pids)
    print("exp: all bessd started")

    # Run all workers
    pids = []
    for i, wip in enumerate(selected_worker_ips):
        # p = multiprocessing.Process(target=start_dummy_worker, args=(wip,))
        p = multiprocessing.Process(target=start_ironside_worker, args=(wip, i, slo, short_profile, long_profile))
        p.start()
        pids.append(p)
    wait_pids(pids)
    print("exp: all workers started")

    # mode: 0 min core; 1 min traffic; 2 max core; 3 max traffic
    ig_mode_text = ["min core", "min traffic", "max core", "max traffic"]
    slo_to_pkt_thresh = {100000: 2000000, 200000: 2000000, 300000: 3000000, 400000: 3000000, 500000: 3000000, 600000: 3000000}
    ig_mode = 3
    for tip in traffic_ip:
        start_traffic_ironside_ingress(tip, num_worker, ig_mode, slo_to_pkt_thresh[slo])
    print("exp: traffic started")

    time.sleep(exp_duration)

    measure_results = parse_latency_result(traffic_ip[0])
    if len(measure_results) == 0:
        print("- Ironside rack-scale exp: no result - ")
        return

    total_packets = measure_results[0]
    delay = measure_results[1:]
    core_usage = []
    for i, wip in enumerate(selected_worker_ips):
        core_usage.append(parse_cpu_time_result(wip) * 3 / 1000)
    avg_cores = sum(core_usage) / 1000000.0 / exp_duration

    print("---------------------------------------------------------------")
    print("- Ironside rack-scale exp result {}".format(slo))
    print("- {} Ironside workers".format(num_worker))
    print("- ingress mode: {} '{}'".format(ig_mode, ig_mode_text[ig_mode]))
    print("- total packets: {}".format(total_packets))
    print("- pkt delay (in us): {}".format(delay))
    print("- core usage (in us): {}".format(core_usage))
    print("- core usage sum (in us): {}".format(sum(core_usage)))
    print("- avg core usage (in cores): {}".format(avg_cores))
    print("---------------------------------------------------------------")
    # 50, 90, 95, 98, 99
    return (slo/1000, avg_cores, total_packets/1000000.0, delay)

def run_metron_exp(num_worker, slo=1000000):
    exp_duration = 50
    selected_worker_ips = []
    for i in range(num_worker):
        selected_worker_ips.append(worker_ip[i])

    # Start all bessd
    pids = []
    for tip in traffic_ip:
        p = multiprocessing.Process(target=start_remote_bessd, args=(tip,))
        p.start()
        pids.append(p)
    for wip in worker_ip:
        p = multiprocessing.Process(target=start_remote_bessd, args=(wip,))
        p.start()
        pids.append(p)
    wait_pids(pids)
    print("exp: all bessd started")

    # Run all workers
    pids = []
    for i, wip in enumerate(selected_worker_ips):
        p = multiprocessing.Process(target=start_metron_worker, args=(wip, i))
        p.start()
        pids.append(p)
    wait_pids(pids)
    print("exp: all workers started")

    # Metron
    ig_mode = 0
    for tip in traffic_ip:
        start_traffic_metron_ingress(tip, num_worker, ig_mode)
    print("exp: traffic started")

    time.sleep(exp_duration)

    measure_results = parse_latency_result(traffic_ip[0])
    if len(measure_results) == 0:
        print("- Ironside rack-scale exp: no result - ")
        return

    total_packets = measure_results[0]
    delay = measure_results[1:]
    core_usage = []
    for i, wip in enumerate(selected_worker_ips):
        core_usage.append(parse_cpu_time_result(wip, 'mcore0') * 3 / 1000)
    avg_cores = sum(core_usage) / 1000000.0 / exp_duration + len(selected_worker_ips) * 3

    print("---------------------------------------------------------------")
    print("- Metron rack-scale exp result {}".format(slo))
    print("- {} Metron workers".format(num_worker))
    print("- total packets: {}".format(total_packets))
    print("- pkt delay (in us): {}".format(delay))
    print("- core usage (in us): {}".format(core_usage))
    print("- core usage sum (in us): {}".format(sum(core_usage)))
    print("- avg core usage (in cores): {}".format(avg_cores))
    print("---------------------------------------------------------------")
    return (slo/1000, avg_cores, total_packets/1000000.0, delay)

def run_quadrant_exp(num_worker, slo):
    exp_duration = 50
    selected_worker_ips = []
    for i in range(num_worker):
        selected_worker_ips.append(worker_ip[i])

    # Start all bessd
    pids = []
    for tip in traffic_ip:
        p = multiprocessing.Process(target=start_remote_bessd, args=(tip,))
        p.start()
        pids.append(p)
    for wip in worker_ip:
        p = multiprocessing.Process(target=start_remote_bessd, args=(wip,))
        p.start()
        pids.append(p)
    wait_pids(pids)
    print("exp: all bessd started")

    # Run all workers
    pids = []
    for i, wip in enumerate(selected_worker_ips):
        p = multiprocessing.Process(target=start_quadrant_worker, args=(wip, i))
        p.start()
        pids.append(p)
    wait_pids(pids)
    print("exp: all workers started")

    # Quadrant
    ig_mode = 1
    for tip in traffic_ip:
        start_traffic_quadrant_ingress(tip, num_worker, ig_mode, slo)
    print("exp: traffic started")

    time.sleep(exp_duration)

    measure_results = parse_latency_result(traffic_ip[0])
    if len(measure_results) == 0:
        print("- Ironside rack-scale exp: no result - ")
        return

    total_packets = measure_results[0]
    delay = measure_results[1:]
    core_usage = []
    for i, wip in enumerate(selected_worker_ips):
        core_usage.append(parse_cpu_time_result(wip, 'mcore0') * 3 / 1000)
    avg_cores = sum(core_usage) / 1000000.0 / exp_duration + len(selected_worker_ips) * 3

    print("---------------------------------------------------------------")
    print("- Quadrant rack-scale exp result {}".format(slo))
    print("- {} Quadrant workers".format(num_worker))
    print("- total packets: {}".format(total_packets))
    print("- pkt delay (in us): {}".format(delay))
    print("- core usage (in us): {}".format(core_usage))
    print("- core usage sum (in us): {}".format(sum(core_usage)))
    print("- avg core usage (in cores): {}".format(avg_cores))
    print("---------------------------------------------------------------")
    return (slo/1000, avg_cores, total_packets/1000000.0, delay)

def run_dyssect_exp(num_worker, slo):
    exp_duration = 50
    selected_worker_ips = []
    for i in range(num_worker):
        selected_worker_ips.append(worker_ip[i])

    # Start all bessd
    pids = []
    for tip in traffic_ip:
        p = multiprocessing.Process(target=start_remote_bessd, args=(tip,))
        p.start()
        pids.append(p)
    wait_pids(pids)
    print("exp: all bessd (only traffic) started")

    # Run all workers
    pids = []
    for i, wip in enumerate(selected_worker_ips):
        p = multiprocessing.Process(target=start_dyssect_worker, args=(wip, i, slo))
        p.start()
        pids.append(p)
    wait_pids(pids)
    print("exp: all workers started")

    # Dyssect
    ig_mode = 2
    for tip in traffic_ip:
        start_traffic_metron_ingress(tip, num_worker, ig_mode)
    print("exp: traffic started")

    time.sleep(exp_duration)

    measure_results = parse_latency_result(traffic_ip[0])
    if len(measure_results) == 0:
        print("- Dyssect rack-scale exp: no result - ")
        return

    total_packets = measure_results[0]
    delay = measure_results[1:]
    core_usage = []
    for i, wip in enumerate(selected_worker_ips):
        core_usage.append(parse_cpu_time_result(wip, 'dyssect') * 3 / 1000)
    avg_cores = sum(core_usage) / 1000000.0 / exp_duration

    print("---------------------------------------------------------------")
    print("- Dyssect rack-scale exp result {}".format(slo))
    print("- {} Dyssect workers".format(num_worker))
    print("- total packets: {}".format(total_packets))
    print("- pkt delay (in us): {}".format(delay))
    print("- core usage (in us): {}".format(core_usage))
    print("- core usage sum (in us): {}".format(sum(core_usage)))
    print("- avg core usage (in cores): {}".format(avg_cores))
    print("---------------------------------------------------------------")
    return (slo/1000, avg_cores, total_packets/1000000.0, delay)


# Main experiment
def run_test_exp():
    worker_cnt = 3
    target_slos = [300000]

    exp_results = []
    for slo in target_slos:
        slo_us = slo / 1000
        short_prof = "./nf_profiles/{}/short_{}.pro".format(NF_CHAIN, slo_us)
        long_prof = "./nf_profiles/{}/long_{}_p50.pro".format(NF_CHAIN, slo_us)
        r = run_cluster_exp(worker_cnt, slo, short_prof, long_prof)
        if r == None:
            continue
        exp_results.append(r)

    if len(exp_results) == 0:
        print("----------       Ironside exp: no results        ----------")
        return

    print("----------     Ironside test experiment results      ----------")
    for r in exp_results:
        print("{} us - {:0.2f}, {:0.2f}, {}".format(r[0], r[1], r[2], r[3]))
    print("---------------------------------------------------------------")
    return

def run_main_exp():
    worker_cnt = 3
    target_slos = [100000, 200000, 300000, 400000, 500000, 600000]

    ironside_results = []
    for slo in target_slos:
        slo_us = slo / 1000
        short_prof = "./nf_profiles/{}/short_{}.pro".format(NF_CHAIN, slo_us)
        long_prof = "./nf_profiles/{}/long_{}_p50.pro".format(NF_CHAIN, slo_us)
        r = run_cluster_exp(worker_cnt, slo, short_prof, long_prof)
        if r == None:
            continue
        ironside_results.append(r)

    if len(ironside_results) == 0:
        print("----------       Ironside exp: no results        ----------")
        return

    print("----------     Ironside main experiment results      ----------")
    for r in ironside_results:
        print("{} us - {:0.2f}, {:0.2f}, {}".format(r[0], r[1], r[2], r[3]))
    print("---------------------------------------------------------------")
    return

def run_compare_exp():
    worker_cnt = 3
    # target_slos = [100000, 200000, 300000, 400000, 500000, 600000]
    target_slos = [100000]

    run_metron = False
    run_quadrant = True
    run_dyssect = False

    metron_results = []
    dyssect_results = []
    quadrant_results = []

    if run_metron:
        metron_results.append(run_metron_exp(worker_cnt))
    if run_quadrant:
        for slo in target_slos:
            r = run_quadrant_exp(worker_cnt, slo)
            quadrant_results.append(r)
    if run_dyssect:
        for slo in target_slos:
            # Dyssect is unstable sometimes, in which case its controller
            # stops working and stops updating core usage info.
            total_trials = 0
            while total_trials < 10:
                r = run_dyssect_exp(1, slo)
                if r[1] > 24:
                    dyssect_results.append(r)
                    break
                total_trials += 1

    if len(metron_results) > 0:
        print("--------        Comparison experiment: Metron         ---------")
        for r in metron_results:
            print("{} us - {:0.2f}, {:0.2f}, {}".format(r[0], r[1], r[2], r[3]))
    if len(quadrant_results) > 0:
        print("--------        Comparison experiment: Quadrant      ----------")
        for r in quadrant_results:
            print("{} us - {:0.2f}, {:0.2f}, {}".format(r[0], r[1], r[2], r[3]))
    if len(dyssect_results) > 0:
        print("--------        Comparison experiment: Dyssect       ----------")
        for r in dyssect_results:
            print("{} us - {:0.2f}, {:0.2f}, {}".format(r[0], r[1], r[2], r[3]))

    print("---------------------------------------------------------------")
    return

# Ablation experiments
def run_ablation_server_mapper():
    worker_cnt = 3
    target_slos = [100000, 200000, 300000, 400000, 500000, 600000]

    exp_results = []
    for slo in target_slos:
        slo_us = slo / 1000
        # Ironside
        short_prof = "./nf_profiles/{}/short_{}.pro".format(NF_CHAIN, slo_us)
        long_prof = "./nf_profiles/{}/long_{}_p50.pro".format(NF_CHAIN, slo_us)
        r1 = run_cluster_exp(worker_cnt, slo, short_prof, long_prof)

        # Static-safe: higher cpu usage
        # It uses more dedicated cores, and less on-demand cores.
        short_prof = "./nf_profiles/{}/short_{}.pro".format(NF_CHAIN, slo_us)
        long_prof = "./nf_profiles/{}/long_{}_p50_safe.pro".format(NF_CHAIN, slo_us)
        r2 = run_cluster_exp(worker_cnt, slo, short_prof, long_prof)

        # Static-unsafe: higher cpu usage?
        # Suppose the core mapepr can handle excessive loads on a dedicated core.
        # Latency should be okay. However, more packet migrations are required,
        # which requires a slightly higher CPU core usage.
        short_prof = "./nf_profiles/{}/short_{}.pro".format(NF_CHAIN, slo_us)
        long_prof = "./nf_profiles/{}/long_{}_p50_unsafe.pro".format(NF_CHAIN, slo_us)
        r3 = run_cluster_exp(worker_cnt, slo, short_prof, long_prof)

        exp_results.append([r1, r2, r3])

    if len(exp_results) == 0:
        print("----------       Ironside exp: no results        ----------")
        return

    print("-------         Ablation experiment results          ----------")
    for i in range(len(exp_results)):
        r1, r2, r3 = exp_results[i]
        slo_us = r1[0]
        print("SLO: {} us".format(slo_us))
        print("      - ironside       {:0.2f}, {:0.2f}, {}".format(r1[1], r1[2], r1[3]))
        print("      - safe           {:0.2f}, {:0.2f}, {}".format(r2[1], r2[2], r2[3]))
        print("      - unsafe         {:0.2f}, {:0.2f}, {}".format(r3[1], r3[2], r3[3]))
    print("---------------------------------------------------------------")
    return

def run_ablation_core_mapper():
    worker_cnt = 3
    target_slos = [100000, 200000, 300000, 400000, 500000, 600000]

    exp_results = []
    exp_results = []
    for slo in target_slos:
        slo_us = slo / 1000
        # Ironside
        short_prof = "./nf_profiles/{}/short_{}.pro".format(NF_CHAIN, slo_us)
        long_prof = "./nf_profiles/{}/long_{}_p50.pro".format(NF_CHAIN, slo_us)
        r1 = run_cluster_exp(worker_cnt, slo, short_prof, long_prof)

        # Static-safe: similar latency && higher cpu usage
        short_prof = "./nf_profiles/{}/short_{}_safe.pro".format(NF_CHAIN, slo_us)
        long_prof = "./nf_profiles/{}/long_{}_p50.pro".format(NF_CHAIN, slo_us)
        r2 = run_cluster_exp(worker_cnt, slo, short_prof, long_prof)

        # Static-unsafe: higher latency
        short_prof = "./nf_profiles/{}/short_{}_unsafe.pro".format(NF_CHAIN, slo_us)
        long_prof = "./nf_profiles/{}/long_{}_p50.pro".format(NF_CHAIN, slo_us)
        r3 = run_cluster_exp(worker_cnt, slo, short_prof, long_prof)

        # No core mapper: super high latency
        short_prof = "./nf_profiles/{}/short_term_baNF_CHAIN, se.pro"
        long_prof = "./nf_profiles/{}/long_{}_p50.pro".format(NF_CHAIN, slo_us)
        r4 = run_cluster_exp(worker_cnt, slo, short_prof, long_prof)

        exp_results.append((r1, r2, r3, r4))

    if len(exp_results) == 0:
        print("----------       Ironside exp: no results        ----------")
        return

    print("-------         Ablation experiment results          ----------")
    for i in range(len(exp_results)):
        r1, r2, r3, r4 = exp_results[i]
        slo_us = r1[0]
        print("SLO: {} us".format(slo_us))
        print("      - ironside       {:0.2f}, {:0.2f}, {}".format(r1[1], r1[2], r1[3]))
        print("      - safe           {:0.2f}, {:0.2f}, {}".format(r2[1], r2[2], r2[3]))
        print("      - unsafe         {:0.2f}, {:0.2f}, {}".format(r3[1], r3[2], r3[3]))
        print("      - no core-mapper {:0.2f}, {:0.2f}, {}".format(r4[1], r4[2], r4[3]))
    print("---------------------------------------------------------------")
    return

def main():
    ## Pre-install
    # reset_grub_for_all()
    # install_mlnx_for_all()
    # get_macs_for_all()
    # fetch_bess_for_all()
    install_bess_for_all()

    ## Config
    # setup_cpu_hugepage_for_all()
    # fetch_traffic_trace(traffic_ip[0])

    ## Ready to produce traffic
    # run_traffic()

    ## Ready to profile an NF chain
    # run_long_profile_under_slos()
    # run_short_profile_under_slos()

    # Main: latency-efficiency comparisons
    # run_test_exp()
    run_main_exp()
    # run_compare_exp()

    # Ablation: the server mapper
    # run_ablation_server_mapper()

    # Ablation: the core mapper
    # run_ablation_core_mapper()
    return

if __name__ == "__main__":
    main()
