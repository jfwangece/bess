import os
import sys
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from collections import OrderedDict

FIGURE_ID = 0
DUMP_NF_PROFILE = True
PLOT_NF_PROFILE = False
LATENCY_PERCENTILES = range(100)

def read_nf_profile(file_name):
    latency_results = []
    with open(file_name) as f:
        lines = f.readlines()
        for line in lines:
            if "Results" in line or "P50" in line or len(line) <= 80:
                continue
            nums = []
            for x in line.split(" "):
                if len(x.strip()) > 0:
                    nums.append(float(x))
            if len(nums) != 3 + len(LATENCY_PERCENTILES):
                continue
            # pkt_size, pkt_rate, and flow_count
            inputs = nums[:3]
            # latency numbers are converted from nsec to usec
            outputs = [x / 1000.0 for x in nums[3:]]
            latency_results.append((inputs, outputs))
        f.close()
    return latency_results

# |target_pkt_sizes|: the target average packet size in bytes.
# |target_slo|: the target latency SLO in usec.
def get_long_term_profile(latency_results, target_pkt_size, target_slo):
    global FIGURE_ID

    max_rate_under_fc = {}
    for i, exp in enumerate(latency_results):
        inputs, outputs = exp
        pkt_size = int(inputs[0])
        pkt_rate = int(inputs[1])
        flow_count = int(inputs[2])
        pval = outputs[49]
        if pkt_size != target_pkt_size:
            continue
        if pval >= target_slo:
            continue
        if flow_count not in max_rate_under_fc:
            max_rate_under_fc[flow_count] = pkt_rate
        else:
            max_rate_under_fc[flow_count] = max(max_rate_under_fc[flow_count], pkt_rate)

    fcs = sorted(max_rate_under_fc.keys())
    rates = [max_rate_under_fc[fc] for fc in fcs]

    fname = "long_term_psize{}_slo{}".format(int(target_pkt_size), int(target_slo))
    if PLOT_NF_PROFILE:
        # write to a png file
        FIGURE_ID += 1
        plt.figure(FIGURE_ID)
        plt.plot(fcs, rates, "x")
        plt.grid(True)
        plt.xlabel("# of active flows")
        plt.ylabel("Max packet rate (pps)")
        plt.title("pkt size = {}; target SLO = {}".format(target_pkt_size, target_slo))
        plt.savefig(fname + ".png", bbox_inches='tight', dpi=300)

    if DUMP_NF_PROFILE:
        # write to a pro file
        with open(fname + ".pro", "w+") as fp:
            for fc in fcs:
                fp.write("%d %d\n" %(fc, max_rate_under_fc[fc]))
            fp.close()
    return

def main():
    if len(sys.argv) != 3 and len(sys.argv) != 2:
        print("usage: python long_term_profile.py <profile-filename> <target-slo>")
        return

    target_pkt_size = 1050
    latency_results = read_nf_profile(sys.argv[1])
    if len(sys.argv) == 3:
        slo = float(sys.argv[2])
        get_long_term_profile(latency_results, target_pkt_size, slo)
    if len(sys.argv) == 2:
        slos = [100.0, 200.0, 400.0, 600.0, 1000.0]
        for slo in slos:
            get_long_term_profile(latency_results, target_pkt_size, slo)
    return

if __name__ == "__main__":
    main()
