#!/usr/bin/env python
import sys
import math
import matplotlib
matplotlib.use('TkAgg', force=True)
import matplotlib.pyplot as plt
from utils import Snapshot, read_cluster_snapshot

# NF chain per-packet cycle cost (worst-case under the maximum):
#
# Chain 2:
# 11972.276 cycles / packet
#
# Chain 4:
# 2632.455 cycles / packet
#
# Chain 5:
# ?
#

# |y_data| is an list of tuple (data, color).
def scatter_group_plot(x_data,
                       y_data_list,
                       x_label="",
                       y_label="",
                       title="",
                       yscale_log=False):
    # Create the plot object
    _, ax = plt.subplots()
    # Plot the data, set the size (s), color and transparency (alpha)
    ax.scatter([0], [0], s=10, marker='o', color='b', alpha=0.75)

    for y_data, y_color in y_data_list:
        ax.scatter(x_data, y_data, s=10, marker='x', color=y_color, alpha=0.75)
        #ax.plot(x_data, y_data, lw=1.0, color=y_color, alpha=1)

    if yscale_log == True:
        ax.set_yscale('log')
    ax.set_title(title)
    ax.set_xlabel(x_label)
    ax.set_ylabel(y_label)
    plt.grid(True)

def scatter_group_curve_plot(x_data,
                       y_data_list,
                       x_label="",
                       y_label="",
                       title="",
                       yscale_log=False):
    # Create the plot object
    _, ax = plt.subplots()
    # Plot the data, set the size (s), color and transparency (alpha)
    ax.scatter([0], [0], s=10, marker='o', color='b', alpha=0.75)

    for y_data, y_color in y_data_list:
        ax.scatter(x_data, y_data, s=10, marker='x', color=y_color, alpha=0.75)
        #ax.plot(x_data, y_data, lw=1.0, color=y_color, alpha=1)

    if yscale_log == True:
        ax.set_yscale('log')
    ax.set_title(title)
    ax.set_xlabel(x_label)
    ax.set_ylabel(y_label)
    plt.grid(True)

def generate_cpu_usage_plot(x, y):
    scatter_group_plot(x, [(y, 'b')], "Epoch", "Core #", "Timeline of CPU core usage", False)

def generate_packet_rate_plot(x, y):
    scatter_group_plot(x, [(y, 'r')], "Epoch", "Pkt rate (pkts / 200 us)", "Timeline of CPU core usage", False)

def generate_core_min_usage_plot(x, y):
    scatter_group_plot(x, [(y, 'b')], "Epoch", "Core #", "Timeline of CPU core usage", False)
    plt.savefig('core_min_usage.png', dpi=300)

def compute_avg_core(y):
    n = len(y)
    sum_core = 0.0
    for core in y:
        sum_core += core
    return sum_core / float(n)

def main():
    stats_filename = "stats.txt"
    if len(sys.argv) >= 2:
        stats_filename = sys.argv[1]

    epoch_usec = 200
    cpu_freq = 1700 # 1 us = |cpu_freq| cycles
    per_core_rate = 680000 * 0.85
    per_packet_cycle_cost = 2632

    print("Input stats file: %s" %(stats_filename))
    snapshots = read_cluster_snapshot(stats_filename)
    x = [i for i in range(len(snapshots))]
    y1 = [s._core_cnt for s in snapshots]
    y2 = [s._pkt_rate for s in snapshots]
    y3 = [math.ceil(s._pkt_rate * per_packet_cycle_cost / (epoch_usec * cpu_freq)) for s in snapshots]

    #generate_cpu_usage_plot(x, y1)
    #generate_packet_rate_plot(x, y2)
    generate_core_min_usage_plot(x, y3)

    print("Min avg core: %f" %(compute_avg_core(y3)))
    return

if __name__ == '__main__':
    main()
