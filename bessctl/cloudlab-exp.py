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

# Cluster 2 (r6525)
dev = "81:00.0"
traffic_ip = ["130.127.134.101"]
worker_ip = ["130.127.134.83", "130.127.134.76", "130.127.134.96", "130.127.134.87"]
all_ip = traffic_ip + worker_ip

# Places to edit MACs
# * in cloud_pcap_relay.pcap: edit macs
# * in nfv_ctrl_long.cc: edit traffic dst mac
macs = ["b8:ce:f6:d2:3a:ba", "b8:ce:f6:b0:35:e2", "b8:ce:f6:d2:3a:c2", "b8:ce:f6:cc:8e:cc", "b8:ce:f6:cc:a2:e4"]

def send_remote_file(ip, local_path, target_path):
    remote_cmd = ['scp', local_path, 'uscnsl@{}:{}'.format(ip, target_path), '>/dev/null', '2>&1', '\n']
    os.system(' '.join(remote_cmd))
    return

def run_remote_command(ip, cmd):
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


def get_mac_from_server(ip):
    cmd = "ifconfig | grep 10.10 -A 2 | grep eth"
    run_remote_command_with_output(ip, cmd)
    return

def reset_grub(ip):
    print("Reset grub conf for {}".format(ip))

    cmd = "git clone https://github.com/jwangee/FaaS-Setup.git"
    run_remote_command(ip, cmd)
    cmd = "cd ./FaaS-Setup && git pull && ./ironside-update-grub.sh"
    run_remote_command(ip, cmd)

def install_mlnx(ip):
    print("Install MLNX OFED for {}".format(ip))

    cmd = "sudo apt install -y htop git"
    run_remote_command(ip, cmd)
    cmd = "git clone https://github.com/jwangee/FaaS-Setup.git"
    run_remote_command(ip, cmd)
    cmd = "cd ./FaaS-Setup && git pull && ./mlnx-ofed-install.sh"
    run_remote_command(ip, cmd)
    return

def install_bess(recompile, ip):
    print("Install BESS daemon for {}".format(ip))

    if recompile:
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

def start_remote_bessd(ip):
    bessd = "/local/bess/core/bessd"
    bessd_cmd = "sudo {} --dpdk=true --buffers=262144 -k".format(bessd)
    run_remote_command(ip, bessd_cmd)
    return

def start_traffic(tip, num_worker, mode):
    cmds = ["run", "nfvctrl/cloud_pcap_replay", "BESS_NUM_WORKER={}, BESS_IG={}".format(num_worker, mode)]
    p = run_remote_besscmd(tip, cmds)
    out, err = p.communicate()
    print(out)
    print("traffic {} starts".format(tip))

def start_flowgen(tip, flow, rate):
    cmds = ["run", "nfvctrl/cloud_flowgen BESS_FLOW={}, BESS_PKT_RATE={}".format(flow, rate)]
    p = run_remote_besscmd(tip, cmds)
    out, err = p.communicate()
    print(out)
    print("flowgen {} starts".format(tip))

def start_ironside_worker(wip, worker_id, slo, short, long, exp_id=0):
    remote_short = "/local/bess/short.prof"
    remote_long = "/local/bess/long.prof"
    send_remote_file(wip, short, remote_short)
    send_remote_file(wip, long, remote_long)
    print("ironside worker {} gets short-term and long-term profiles".format(worker_id))

    cmds = ["run", "nfvctrl/cloud_chain4"]
    if exp_id == 0:
        extra_cmd = "TRAFFIC_MAC='{}', BESS_WID={}, BESS_SLO={}, BESS_SPROFILE='{}', BESS_LPROFILE='{}'".format(macs[0], worker_id, slo, remote_short, remote_long)
        cmds.append(extra_cmd)
    else:
        extra_cmd = "TRAFFIC_MAC='{}', BESS_WID={}, BESS_SLO={}, BESS_SPROFILE='{}', BESS_LPROFILE='{}', BESS_EXP_ID={}".format(macs[0], worker_id, slo, remote_short, remote_long, exp_id)
        cmds.append(extra_cmd)
    p = run_remote_besscmd(wip, cmds)
    out, err = p.communicate()
    # print(out)
    print("ironside worker {} starts".format(wip))

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

def parse_cpu_time_result(wip):
    cmds = ['command', 'module', 'nfv_core0', 'get_core_time', 'EmptyArg']
    p = run_remote_besscmd(wip, cmds)
    out, err = p.communicate()
    lines = out.split('\n')
    for line in lines:
        if 'core_time' in line:
            return int(line.split(':')[2].strip())
    return 0

def get_macs_for_all():
    # Run remote commands one at a time.
    ips = traffic_ip + worker_ip
    for ip in ips:
        get_mac_from_server(ip)
    print("Done getting MACs")
    return

def reset_grub_for_all():
    # install mlnx ofed
    pids = []
    for ip in all_ip:
        p = multiprocessing.Process(target=reset_grub, args=(ip,))
        p.start()
        pids.append(p)

    for p in pids:
        p.join()

    print("Done resetting grub")
    return

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
        p = multiprocessing.Process(target=install_bess, args=(True, ip,))
        p.start()
        pids.append(p)

    for p in pids:
        p.join()
    print("Done installing ironside")
    return

def fetch_bess_for_all():
    # install ironside bessd
    pids = []
    for ip in all_ip:
        p = multiprocessing.Process(target=install_bess, args=(False, ip,))
        p.start()
        pids.append(p)

    for p in pids:
        p.join()
    print("Done fetching ironside configures")
    return

def fetch_traffic_trace():
    # transmit all traffic traces used in the evaluation
    trace1 = "./experiment_conf/20190117-130000.tcp.pcap"
    dst1 = "uscnsl@{}:/local/bess/experiment_conf".format(traffic_ip[0])
    local_cmd = ["scp", trace1, dst1]
    os.system(' '.join(local_cmd))

    print("Done fetching traffic traces")
    return

def setup_cpu_hugepage_for_all():
    # hugepage all servers
    pids = []
    for ip in all_ip:
        p = multiprocessing.Process(target=setup_cpu_memory, args=(ip,))
        p.start()
        pids.append(p)

    for p in pids:
        p.join()
    print("exp: all hugepages ready")
    return

def run_traffic():
    pids = []
    for tip in traffic_ip:
        p = multiprocessing.Process(target=start_remote_bessd, args=(tip,))
        p.start()
        pids.append(p)
    for p in pids:
        p.join()

    for tip in traffic_ip:
        start_traffic(tip)
    print("exp: traffic started")

    time.sleep(30)

    delay = parse_latency_result(traffic_ip[0])
    print("delay (in us): {}".format(delay))

    print("exp: done")
    return delay

## Profile helper
def profile_once(slo, flow, pkt_rate):
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
    for p in pids:
        p.join()
    print("exp: all bessd started")

    # Run all workers
    short_profile = "./nf_profiles/short_term_base.pro"
    long_profile = "./nf_profiles/long_term_base.pro"
    pids = []
    for i, wip in enumerate(selected_worker_ips):
        p = multiprocessing.Process(target=start_ironside_worker, args=(wip, i, slo, short_profile, long_profile))
        p.start()
        pids.append(p)
    for p in pids:
        p.join()
    print("exp: all workers started")

    total_flow = flow
    total_pkt_rate = pkt_rate
    for tip in traffic_ip:
        start_flowgen(tip, total_flow, total_pkt_rate)
    print("exp: traffic started")

    time.sleep(15)

    measure_results = parse_latency_result(traffic_ip[0])
    if len(measure_results) == 0:
        print("- Ironside rack-scale exp: no result - ")
        return

    total_packets = measure_results[0]
    delay = measure_results[1:]
    core_usage = []
    for i, wip in enumerate(selected_worker_ips):
        core_usage.append(parse_cpu_time_result(wip) / 1000)
    avg_core_usage = sum(core_usage) / 1000000.0 / 30

    print("- Ironside worker-scale profile result -")
    print("flowgen: flows={}, rate={}".format(flow, pkt_rate))
    print("total packets: {}".format(total_packets))
    print("pkt delay (in us): {}".format(delay))
    print("core usage (in us): {}".format(core_usage))
    print("core usage sum (in us): {}".format(sum(core_usage)))
    print("avg core usage: {}".format(avg_core_usage))
    print("- Ironside worker-scale profile end -")
    return (delay[0], delay[1])

# Profile an NF chain's single-core performance in a cross-machine setting.
# The input determines the target latency SLO and traffic input metrics.
# |flow_range|: a list of active flow counts to profile.
# |rate_range|: a list of packet rates to profile.
def run_long_term_profile(slo, flow_range, rate_range):
    start_time = time.time()

    nf_profile_p50 = {}
    nf_profile_p90 = {}
    for f in sorted(flow_range):
        for r in sorted(rate_range):
            delay = profile_once(slo, f, r)
            if len(delay) == 0:
                continue
            if delay[1] * 1000 <= slo:
                nf_profile_p90[f] = r
            if delay[0] * 1000 <= slo:
                nf_profile_p50[f] = r
            else:
                # early break for saving time (|slo| is in ns)
                break

    fp1 = open("./long_{}_p50.pro".format(slo/1000), "w+")
    keys = sorted(nf_profile_p50.keys())
    for key in keys:
        if key not in nf_profile_p50:
            continue
        val = nf_profile_p50[key]
        fp1.write("{} {}\n".format(key ,val))
    fp1.close()

    fp2 = open("./long_{}_p90.pro".format(slo/1000), "w+")
    keys = sorted(nf_profile_p90.keys())
    for key in keys:
        if key not in nf_profile_p90:
            continue
        val = nf_profile_p90[key]
        fp2.write("{} {}\n".format(key ,val))
    fp2.close()

    end_time = time.time()
    diff = int(end_time - start_time)
    print("Total profiling time: {} minutes, {} seconds".format(diff / 60, diff % 60))
    return

def run_worker_exp(slo):
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

    for p in pids:
        p.join()
    print("exp: all bessd started")

    # Run all workers
    short_profile = "./nf_profiles/short_term_base.pro"
    long_profile = "./nf_profiles/long_term_base.pro"
    pids = []
    for i, wip in enumerate(selected_worker_ips):
        p = multiprocessing.Process(target=start_ironside_worker, args=(wip, i, slo, short_profile, long_profile))
        p.start()
        pids.append(p)

    for p in pids:
        p.join()
    print("exp: all workers started")

    flow = 1000
    pkt_rate = 100000
    for tip in traffic_ip:
        start_flowgen(tip, flow, pkt_rate)
    print("exp: traffic started")

    time.sleep(29)

    measure_results = parse_latency_result(traffic_ip[0])
    if len(measure_results) == 0:
        print("- Ironside rack-scale exp: no result - ")
        return

    total_packets = measure_results[0]
    delay = measure_results[1:]
    core_usage = []
    for i, wip in enumerate(selected_worker_ips):
        core_usage.append(parse_cpu_time_result(wip) / 1000)
    avg_core_usage = sum(core_usage) / 1000000.0 / 30

    print("- Ironside worker-scale exp result -")
    print("flowgen: flows={}, rate={}".format(flow, pkt_rate))
    print("total packets: {}".format(total_packets))
    print("pkt delay (in us): {}".format(delay))
    print("core usage (in us): {}".format(core_usage))
    print("core usage sum (in us): {}".format(sum(core_usage)))
    print("avg core usage: {}".format(avg_core_usage))
    print("- Ironside worker-scale exp end -")
    return (delay[0], delay[1])

def run_cluster_exp(num_worker, slo, short_profile, long_profile):
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

    for p in pids:
        p.join()
    print("exp: all bessd started")

    # Run all workers
    pids = []
    for i, wip in enumerate(selected_worker_ips):
        p = multiprocessing.Process(target=start_ironside_worker, args=(wip, i, slo, short_profile, long_profile))
        # p = multiprocessing.Process(target=start_ironside_worker, args=(wip, i, slo, short_profile, long_profile, 1))
        p.start()
        pids.append(p)

    for p in pids:
        p.join()
    print("exp: all workers started")

    # mode: 0 min core; 1 min traffic; 2 max core; 3 max traffic
    ig_mode_text = ["min core", "min traffic", "max core", "max traffic"]
    ig_mode = 3
    for tip in traffic_ip:
        start_traffic(tip, num_worker, ig_mode)
    print("exp: traffic started")

    time.sleep(29)

    measure_results = parse_latency_result(traffic_ip[0])
    if len(measure_results) == 0:
        print("- Ironside rack-scale exp: no result - ")
        return

    total_packets = measure_results[0]
    delay = measure_results[1:]
    core_usage = []
    for i, wip in enumerate(selected_worker_ips):
        core_usage.append(parse_cpu_time_result(wip) * 3 / 1000)
    avg_cores = sum(core_usage) / 1000000.0 / 30.0

    print("- Ironside rack-scale exp result -")
    print("total {} Ironside workers".format(num_worker))
    print("ingress mode: {} '{}'".format(ig_mode, ig_mode_text[ig_mode]))
    print("total packets: {}".format(total_packets))
    print("pkt delay (in us): {}".format(delay))
    print("core usage (in us): {}".format(core_usage))
    print("core usage sum (in us): {}".format(sum(core_usage)))
    print("avg core usage (in cores): {}".format(avg_cores))
    print("- Ironside rack-scale exp end -")
    return (delay[-1], avg_cores)

def run_ablation_server_mapper():
    worker_cnt = 4
    results = []
    # all_slo = [200000, 300000, 400000, 500000]
    all_slo = [200000]

    for slo in all_slo:
        slo_us = slo/1000
        # Ironside
        short_prof = "./nf_profiles/short_term_slo{}.pro".format(slo_us)
        long_prof = "./nf_profiles/long_{}_p50.pro".format(slo_us)
        r1 = run_cluster_exp(worker_cnt, slo, short_prof, long_prof)

        # Static-safe: higher cpu usage
        # It uses more dedicated cores, and less on-demand cores.
        short_prof = "./nf_profiles/short_term_slo{}.pro".format(slo_us)
        long_prof = "./nf_profiles/long_{}_p50.pro".format(slo_us)
        r2 = run_cluster_exp(worker_cnt, slo, short_prof, long_prof)

        # Static-unsafe: higher cpu usage?
        # Suppose the core mapepr is able to handle the excessive load on a
        # dedicated core. Then, the latency should be okay. However, more
        # packet migrations are required, which requires a slightly higher
        # CPU core usage.
        short_prof = "./nf_profiles/short_term_slo{}.pro".format(slo_us)
        long_prof = "./nf_profiles/long_{}_p50.pro".format(slo_us)
        r3 = run_cluster_exp(worker_cnt, slo, short_prof, long_prof)

        results.append([slo, r1, r2, r3])

    print(results)
    return

def run_ablation_core_mapper():
    return

def main():
    ## Pre-install
    # reset_grub_for_all()
    # install_mlnx_for_all()
    # get_macs_for_all()
    install_bess_for_all()
    # fetch_bess_for_all()

    ## Config
    # setup_cpu_hugepage_for_all()
    # fetch_traffic_trace()

    ## Ready to produce traffic
    # run_traffic()

    ## Ready to profile an NF chain
    # slo = 100000
    # flow_range = range(500, 4000, 500)
    # rate_range = range(1100000, 1800000, 50000)
    # run_long_term_profile(slo, flow_range, rate_range)

    # slo = 200000
    # flow_range = range(500, 4000, 500)
    # rate_range = range(1100000, 1800000, 20000)
    # run_long_term_profile(slo, flow_range, rate_range)

    # slo = 300000
    # flow_range = range(500, 4000, 500)
    # rate_range = range(1100000, 1800000, 50000)
    # run_long_term_profile(slo, flow_range, rate_range)

    # slo = 400000
    # flow_range = range(500, 4000, 500)
    # rate_range = range(1100000, 1800000, 50000)
    # run_long_term_profile(slo, flow_range, rate_range)

    # slo = 500000
    # flow_range = range(500, 4000, 500)
    # rate_range = range(1100000, 1800000, 50000)
    # run_long_term_profile(slo, flow_range, rate_range)

    # slo = 600000
    # flow_range = range(500, 4000, 500)
    # rate_range = range(1100000, 2000000, 50000)
    # run_long_term_profile(slo, flow_range, rate_range)

    # slo = 800000
    # flow_range = range(500, 4000, 500)
    # rate_range = range(1100000, 2000000, 50000)
    # run_long_term_profile(slo, flow_range, rate_range)
    # return

    ## Ready to run end-to-end exp
    # worker_cnt = 4
    # slo = 200000
    # short_prof = "./nf_profiles/short_term_slo200.pro"
    # long_prof = "./nf_profiles/long_200_p50.pro"
    # run_cluster_exp(worker_cnt, slo, short_prof, long_prof)

    # worker_cnt = 2
    # slo = 300000
    # short_prof = "./nf_profiles/short_term_slo300.pro"
    # long_prof = "./nf_profiles/long_term_slo300.pro"
    # run_cluster_exp(worker_cnt, slo, short_prof, long_prof)

    # worker_cnt = 3
    # slo = 400000
    # short_prof = "./nf_profiles/short_term_slo400.pro"
    # long_prof = "./nf_profiles/long_term_slo400.pro"
    # run_cluster_exp(worker_cnt, slo, short_prof, long_prof)

    # slo = 500000
    # short_prof = "./nf_profiles/short_term_slo500.pro"
    # long_prof = "./nf_profiles/long_term_slo500.pro"
    # run_cluster_exp(slo, short_prof, long_prof)

    # slo = 600000
    # short_prof = "./nf_profiles/short_term_slo600.pro"
    # long_prof = "./nf_profiles/long_term_slo600.pro"
    # run_cluster_exp(slo, short_prof, long_prof)

    # Ablation: the server mapper
    run_ablation_server_mapper()

    # Ablation: the core mapper
    # run_ablation_core_mapper()
    return

if __name__ == "__main__":
    main()
