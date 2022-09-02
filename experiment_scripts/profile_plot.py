import os
import sys
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from collections import OrderedDict

# Plot NF profile graph (pkt-size / pkt-rate / flow-count ~ latency)
SHOW_DATA_VARY_FLOW_COUNT = False
SHOW_DATA_VARY_PKT_SIZE = False
PLOT_CDF_VARY_FLOW_COUNT = False
PLOT_CDF_VARY_PKT_SIZE = True
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

def aggregate_latency_results(latency_results):
    """This function assumes that each experiment is repeated N times;
       |latency_results| is a list of experimental latency results.
       Suppose there are M different experimental groups; each group
       is repeated N times; then, len(latency_results) is N * M.
       This function aggregates results from runs of the same experimental
       group. It does so by calculating the avg values for CDF percentiles.
    """
    aggregates = OrderedDict()
    for i, latency_result in enumerate(latency_results):
        inputs, outputs = latency_result
        key = str(inputs)
        if key not in aggregates:
            aggregates[key] = [inputs]
        aggregates[key].append(outputs)

    aggregated_results = []
    for key, exps in aggregates.items():
        inputs = exps[0]
        num_latency_vals = len(exps[1])
        num_repetitions = len(exps[1:])
        final_outputs = [0.0 for i in range(num_latency_vals)]
        for i in range(num_latency_vals):
            for exp in exps[1:]:
                final_outputs[i] += exp[i]
            final_outputs[i] /= num_repetitions
        aggregated_results.append((inputs, final_outputs))
    return aggregated_results

def plot_nf_profile(file_name):
    latency_results = read_nf_profile(file_name)
    print("Total samples: {}".format(len(latency_results)))

    # Get all possible input values
    pkt_sizes = []
    pkt_rates = []
    flow_counts = []
    for exp in latency_results:
        inputs, outputs = exp
        ps, pr, fc = inputs
        if ps not in pkt_sizes:
            pkt_sizes.append(ps)
        if pr not in pkt_rates:
            pkt_rates.append(pr)
        if fc not in flow_counts:
            flow_counts.append(fc)
    pkt_sizes.sort()
    pkt_rates.sort()
    flow_counts.sort()

    if SHOW_DATA_VARY_FLOW_COUNT:
        # Vary flow counts
        for ps in pkt_sizes:
            for pr in pkt_rates:
                nums = []
                for exp in latency_results:
                    inputs, outputs = exp
                    if inputs[0] == ps and inputs[1] == pr:
                        nums.append(outputs[0])
                print("pkt size: %d; pkt rate: %d; %s" %(ps, pr, nums))

    if PLOT_CDF_VARY_FLOW_COUNT:
        pkt_size = 500
        pkt_rate = 1000000
        y = [float(p) for p in range(100)]
        plot_legend = []
        # aggregate all experimental repetitions as the avg
        # Note: deprecated; we must not aggregate CDF plots given that
        # all per-packet latency numbers follow an I.I.D distribution.
        # latency_results = aggregate_latency_results(latency_results)
        for i, exp in enumerate(latency_results):
            inputs, outputs = exp
            pkt_size = inputs[0]
            pkt_rate = inputs[1]
            flow_count_label = "Flows: {}".format(inputs[2])
            if inputs[2] not in [600, 1200, 1800, 2400, 3000, 3600]:
                continue
            x = outputs
            plot_legend.append(flow_count_label)
            plt.plot(x, y, '--', linewidth=1.5)
        plt.grid(True)
        plt.xscale('log')
        plt.legend(plot_legend, loc="best", fancybox=True, shadow=True)
        plt.xlabel("Latency (usec)")
        plt.ylabel("Percentiles (%)")
        plt.title("pkt size = {}; pkt rate = {}".format(pkt_size, pkt_rate))
        plt.savefig("latency_cdf.png", bbox_inches='tight', dpi=300)

    if PLOT_CDF_VARY_PKT_SIZE:
        pkt_rate = 1000000
        flow_count = 1000
        y = [float(p) for p in range(100)]
        plot_legend = []
        # aggregate all experimental repetitions as the avg
        # Note: deprecated; we must not aggregate CDF plots given that
        # all per-packet latency numbers follow an I.I.D distribution.
        # latency_results = aggregate_latency_results(latency_results)
        for i, exp in enumerate(latency_results):
            inputs, outputs = exp
            if inputs[0] not in [150, 300, 450, 600, 750, 900, 1050, 1200, 1350]:
                continue
            if inputs[2] not in [1000]:
                continue
            pkt_rate = inputs[1]
            flow_count = inputs[2]
            pkt_size_label = "Pkt size: {}".format(inputs[0])
            x = outputs
            plot_legend.append(pkt_size_label)
            plt.plot(x, y, '--', linewidth=1.5)
        plt.grid(True)
        # plt.xscale('log')
        plt.legend(plot_legend, loc="best", fancybox=True, shadow=True)
        plt.xlabel("Latency (usec)")
        plt.ylabel("Percentiles (%)")
        plt.title("pkt rate = {}; flow count = {}".format(pkt_rate, flow_count))
        plt.savefig("latency_cdf.png", bbox_inches='tight', dpi=300)
    return

def main():
    if len(sys.argv) == 1:
        print("usage: python profile_plot.py <profile-filename>")
        return

    file_name = sys.argv[1]
    plot_nf_profile(file_name)

if __name__ == "__main__":
    main()
