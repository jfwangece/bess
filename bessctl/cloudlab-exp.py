#!/usr/bin/env python
import sys
import os
import io
import multiprocessing
import subprocess
import time
from bessctl import run_cli

INIT_SERVER = False
# CLuster 1
# dev = "41:00.0"
# traffic_ip = ["128.110.219.154"]
# worker_ip = ["128.110.219.147", "128.110.219.145", "128.110.219.148", "128.110.219.131"]

# Cluster 2
dev = "81:00.0"
traffic_ip = ["130.127.134.78"]
worker_ip = ["130.127.134.91", "130.127.134.76", "130.127.134.97", "130.127.134.73"]
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

def install_mlnx(ip):
    print("Install MLNX OFED for {}".format(ip))

    cmd = "sudo apt install -y htop git"
    run_remote_command(ip, cmd)
    cmd = "git clone https://github.com/jwangee/FaaS-Setup.git"
    run_remote_command(ip, cmd)
    cmd = "cd ./FaaS-Setup && git pull && ./mlnx-ofed-install.sh"
    run_remote_command(ip, cmd)
    return

def install_bess(ip):
    print("Install BESS daemon for {}".format(ip))

    cmd = "sudo apt install -y htop git"
    run_remote_command(ip, cmd)
    cmd = "git clone https://github.com/jwangee/FaaS-Setup.git"
    run_remote_command(ip, cmd)
    cmd = "cd ./FaaS-Setup && git pull && ./ironside-install.sh"
    run_remote_command(ip, cmd)
    return

def setup_remote_hugepage(ip):
    print("Setup hugepages for {}".format(ip))

    cmd1 = "echo 4096 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages"
    run_remote_command(ip, cmd1)
    cmd2 = "echo 4096 | sudo tee /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages"
    run_remote_command(ip, cmd2)
    return

def start_traffic(tip):
    cmds = ["run", "nfvctrl/cloud_pcap_replay"]
    p = run_remote_besscmd(tip, cmds)
    out, err = p.communicate()
    print("traffic {} starts".format(tip))

def start_ironside_worker(wip):
    cmds = ["run", "nfvctrl/cloud_chain4"]
    p = run_remote_besscmd(wip, cmds)
    out, err = p.communicate()
    print("ironside worker {} starts".format(wip))

def parse_latency_result(tip):
    cmds = ['command', 'module', 'measure0', 'get_summary', 'MeasureCommandGetSummaryArg', '{"latency_percentiles": [50.0, 90.0, 95.0, 98.0, 99.0]}']
    p = run_remote_besscmd(tip, cmds)
    out, err = p.communicate()
    print(out + "\n")

def install_mlnx_for_all():
    # install mlnx ofed
    pids = []
    for ip in all_ip:
        p = multiprocessing.Process(target=install_mlnx, args=(ip,))
        p.start()
        pids.append(p)

    for p in pids:
        p.join()

    print("Done installing mlnx")
    return

def install_bess_for_all():
    # install ironside bessd
    pids = []
    for ip in all_ip:
        p = multiprocessing.Process(target=install_bess, args=(ip,))
        p.start()
        pids.append(p)

    for p in pids:
        p.join()

    print("Done installing ironside")
    return

def setup_hugepage_for_all():
    # hugepage all servers
    pids = []
    for ip in all_ip:
        p = multiprocessing.Process(target=setup_remote_hugepage, args=(ip,))
        p.start()
        pids.append(p)

    for p in pids:
        p.join()
    print("exp: all hugepages ready")
    return

def run_exp():
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
    print("exp: all bessd started")

    # Run all workers
    pids = []
    for wip in worker_ip:
        p = multiprocessing.Process(target=start_ironside_worker, args=(wip,))
        p.start()
        pids.append(p)

    for p in pids:
        p.join()
    print("exp: all workers started")

    for tip in traffic_ip:
        start_traffic(tip)
    print("exp: traffic started")

    time.sleep(5)

    parse_latency_result(traffic_ip[0])
    print("exp: done")
    return

def main():
    # install_mlnx_for_all()
    # install_bess_for_all()
    # setup_hugepage_for_all()

    run_exp()
    return

if __name__ == "__main__":
    main()
