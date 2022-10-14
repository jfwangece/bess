#!/usr/bin/env python
import sys
import os
import io
import multiprocessing
import subprocess
import time
from bessctl import run_cli

INIT_SERVER = False
traffic_ip = ["128.110.219.148"]
# worker_ip = ["128.110.219.135", "128.110.219.131", "128.110.219.154", "128.110.219.147"]
worker_ip = ["128.110.219.135"]
all_ip = traffic_ip + worker_ip

def run_remote_command(ip, cmd):
    remote_cmd = ['ssh', 'uscnsl@{}'.format(ip), '"{}"'.format(cmd), '>/dev/null', '2>&1', '\n']
    os.system(' '.join(remote_cmd))
    return

def run_remote_besscmd(ip, cmds):
    cmds_str = u' '.join(cmds)
    remote_cmds = ['./bessctl/bessctl.py', ip, cmds_str, '\n']
    p = subprocess.Popen(remote_cmds, universal_newlines=True,
                        stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p

def start_remote_bessd(ip):
    bessd = "/local/bess/core/bessd"
    bessd_cmd = "sudo {} --dpdk=true --buffers=262144 -k".format(bessd)
    run_remote_command(ip, bessd_cmd)
    return

def setup_remote_hugepage(ip):
    cmd1 = "echo 4096 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages"
    run_remote_command(ip, cmd1)
    cmd2 = "echo 4096 | sudo tee /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages"
    run_remote_command(ip, cmd2)
    return

def start_traffic(tip):
    cmds = ["run", "nfvctrl/cloud_pcap_replay"]
    run_remote_besscmd(tip, cmds)

def start_ironside_worker(wip):
    cmds = ["run", "nfvctrl/cloud_chain4"]
    p = run_remote_besscmd(wip, cmds)
    out, err = p.communicate()
    print("ironside {} starts".format(wip))

def parse_latency_result(tip):
    cmds = ['command', 'module', 'measure0', 'get_summary', 'MeasureCommandGetSummaryArg', '{"latency_percentiles": [50.0, 90.0, 95.0, 98, 99.0]}']
    p = run_remote_besscmd(tip, cmds)
    out, err = p.communicate()
    print(out + "\n")

def main():
    # Prepare all servers
    if INIT_SERVER:
        for ip in all_ip:
            setup_remote_hugepage(ip)

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

    for p in pids:
        p.join()
    print("exp: all bessd started\n")

    # Run all workers
    pids = []
    for wip in worker_ip:
        p = multiprocessing.Process(target=start_ironside_worker, args=(wip,))
        p.start()
        pids.append(p)

    for p in pids:
        p.join()
    print("exp: all workers started\n")

    for tip in traffic_ip:
        start_traffic(tip)
    print("exp: traffic started\n")

    time.sleep(30)

    parse_latency_result(traffic_ip[0])
    return

if __name__ == "__main__":
    main()
