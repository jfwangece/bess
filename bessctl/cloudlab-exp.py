#!/usr/bin/env python
import multiprocessing
import sys
import os
import io
from multiprocessing import Process, Queue
import subprocess
from bessctl import run_cli

INIT_SERVER = False
traffic_ip = ["128.110.219.148"]
worker_ip = ["128.110.219.135", "128.110.219.131", "128.110.219.154", "128.110.219.147"]
all_ip = traffic_ip + worker_ip


def run_remote_command(ip, cmd):
    remote_cmd = ['ssh', '-t', 'uscnsl@{}'.format(ip), '"{}"'.format(cmd)]
    os.system(' '.join(remote_cmd))
    return

def run_remote_besscmd(ip, cmds):
    list_cmds = []
    list_cmds.append(u' '.join(cmds))
    run_cli(ip, io.StringIO('\n'.join(list_cmds)))

def start_remote_bessd(ip):
    bessd = "/local/bess/core/bessd"
    bessd_cmd = "sudo -E {} --dpdk=true --buffers=262144 -k".format(bessd)
    run_remote_command(ip, bessd_cmd)
    return

def setup_remote_hugepage(ip):
    cmd1 = "echo 4096 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages"
    cmd2 = "echo 4096 | sudo tee /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages"
    run_remote_command(ip, cmd1)
    run_remote_command(ip, cmd2)
    return

def start_traffic(tip):
    cmds = ["run", "nfvctrl/cloud_pcap_replay"]
    run_remote_besscmd(tip, cmds)

def start_ironside_worker(wip):
    cmds = ["run", "samples/acl"]
    run_remote_besscmd(wip, cmds)

def parse_latency_result(tip):
    cmds = ['command', 'module', 'measure0', 'get_summary', 'MeasureCommandGetSummaryArg', '{"latency_percentiles": [50.0, 90.0, 95.0, 98, 99.0]}']
    run_remote_besscmd(tip, cmds)

def main():
    # Prepare all servers
    if INIT_SERVER:
        for ip in all_ip:
            setup_remote_hugepage(ip)

    # Start all bessd
    for tip in traffic_ip:
        multiprocessing.Process(target=start_remote_bessd, args=(tip))
    for wip in worker_ip:
        multiprocessing.Process(target=start_remote_bessd, args=(wip))
    print("exp: all bessd started")

    # Run all workers
    for wip in worker_ip:
        start_ironside_worker(wip)
    print("exp: all workers started")

    for tip in traffic_ip:
        start_traffic(tip)
    print("exp: traffic started")


    return

if __name__ == "__main__":
    main()
