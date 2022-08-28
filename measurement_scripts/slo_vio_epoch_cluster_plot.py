#!/usr/bin/env python
import sys
import math
import numpy as np
import matplotlib
matplotlib.use('TkAgg', force=True)
import matplotlib.pyplot as plt
from utils import CoreSnapshot, SLOEvent
from utils import read_core_snapshot

stats_dir = "../"

def cluster_plot(node_groups, title=None):
    """ node_groups is a list of node_group.
        Each node group is defined as (marker, color, a list of nodes)
    """
    _, ax = plt.subplots()

    for m,c,s,nodes in node_groups:
        x_data = [node[0] for node in nodes]
        y_data = [node[1] for node in nodes]
        ax.scatter(x_data, y_data, marker=m, color=c, s=s)

    ax.set_xlabel("Packet count")
    ax.set_ylabel("Active flow count")
    if title:
        ax.set_title(title)
    plt.grid(True)


def parse_core_snapshot(core_id):
    stats_filename = "stats%d.txt" %(core_id)
    stats_abs_dir = stats_dir + stats_filename
    snapshots = read_core_snapshot(stats_abs_dir)
    return snapshots

def generate_slo_vio_signal_plot(core_snapshots, title=None):
    """ |core_snapshots| is a list of CoreSnapshot objects
        This function first seperates SLO-violating and non-SLO-violating epochs.
        THen, it calls |cluster_plot| function to generate node clusters in a plot.
    """
    slo_vio_nodes = []
    non_slo_vio_nodes = []
    for i in range(len(core_snapshots)):
        slo, non_slo = slo_vio_analysis(core_snapshots[i])
        slo_vio_nodes += slo
        non_slo_vio_nodes += non_slo

    node_groups = [('x', 'blue', 5, slo_vio_nodes), ('.', 'purple', 1, non_slo_vio_nodes)]
    cluster_plot(node_groups, "blue: SLO-vio epoch; purple: non SLO-vio epoch")
    if title:
        plt.savefig('slo_vio_signal%s.png' %(title), dpi=600)
    else:
        plt.savefig('slo_vio_signal.png', dpi=600)

# Get the (packet count, active flow count) for both non-SLO-violated and SLO-violated epochs.
def slo_vio_analysis(snapshots):
    slo_vio_nodes = []
    non_slo_vio_nodes = []

    n = len(snapshots)
    for sidx in range(1, n-2):
        is_both = 0
        if snapshots[sidx]._slo_violations == 0 and snapshots[sidx+1]._slo_violations == 0 and snapshots[sidx+2]._slo_violations == 0:
            is_both += 1
            non_slo_vio_nodes.append((snapshots[sidx]._pkt_rate, snapshots[sidx]._active_flow_cnt))

        #if snapshots[sidx-1]._slo_violations == 0 and snapshots[sidx]._slo_violations >= 5:
        if snapshots[sidx-1]._slo_violations >= 10 and snapshots[sidx]._slo_violations >= 10 and snapshots[sidx+1]._slo_violations >= 10:
            is_both += 1
            slo_vio_nodes.append((snapshots[sidx]._pkt_rate, snapshots[sidx]._active_flow_cnt))

        if is_both == 2:
            print("Error")

    return (slo_vio_nodes, non_slo_vio_nodes)


def main():
    core_snapshots = []
    for core_id in range(8):
        core_snapshots.append(parse_core_snapshot(core_id))

    # Cluster-scale
    total_epochs = 0
    total_pkts = 0
    short_term_slo_vio_epochs = 0
    short_term_slo_vio_epoch_ratio = 0.0
    short_term_slo_vio_pkts = 0
    short_term_slo_vio_pkt_ratio = 0.0
    long_term_slo_vio_epochs = 0
    long_term_slo_vio_epoch_ratio = 0.0
    long_term_slo_vio_pkts = 0
    long_term_slo_vio_pkt_ratio = 0.0

    all_slo_vio = []
    short_term_slo_vio = []
    long_term_slo_vio = []

    # SLO-violation plot
    for i in range(1, 8):
        generate_slo_vio_signal_plot([core_snapshots[i]], "core%d" %(i))

    return

if __name__ == '__main__':
    main()
