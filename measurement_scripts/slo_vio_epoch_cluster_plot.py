import os
import sys
import math
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from utils import CoreSnapshot, SLOEvent
from utils import read_core_snapshot

stats_dir = "./"

def parse_core_snapshot(core_id):
    stats_filename = "stats%d.txt" %(core_id)
    stats_abs_dir = stats_dir + stats_filename
    snapshots = read_core_snapshot(stats_abs_dir)
    return snapshots

def cluster_plot(node_groups, title=None):
    """ node_groups is a list of node_group.
        Each node group is defined as (marker, color, a list of nodes)
    """
    _, ax = plt.subplots()

    for m,c,s,nodes in node_groups:
        x_data = [node[0] for node in nodes] # flow count
        y_data = [node[1] for node in nodes] # pkt count
        ax.scatter(x_data, y_data, marker=m, color=c, s=s)

    ax.set_xlabel("Flow count")
    ax.set_ylabel("Packet count")

    if title:
        ax.set_title(title)
    plt.grid(True)
    return

def get_short_term_profile(nodes):
    """ Each node is a tuple (flow count, packet count).
    Then, we want to find: given a flow count, the max possible packet count
    that a core can process within an epoch.
    Method:
    1. sort nodes according to their flow counts;
    2. start from the highest flow count, update the max packet count;
    3. set each flow count to be the current max packet count;
    """
    sorted_nodes = sorted(nodes, key=lambda x: x[0])
    max_flow = int(sorted_nodes[-1][0])
    curr_max_pkt_cnt = int(sorted_nodes[-1][1])
    short_term_profile = []
    print(sorted_nodes)

    fc_to_pkt = {}
    for fc, pkt in sorted_nodes:
        fc = int(fc)
        if fc not in fc_to_pkt:
            fc_to_pkt[fc] = int(pkt)
        else:
            fc_to_pkt[fc] = max(fc_to_pkt[fc], int(pkt))

    for i in reversed(range(1, max_flow)):
        if i in fc_to_pkt:
            curr_max_pkt_cnt = max(curr_max_pkt_cnt, fc_to_pkt[i])
        short_term_profile.append((i, curr_max_pkt_cnt))

    short_term_profile = sorted(short_term_profile, key=lambda x: x[0])
    with open("short_profile.txt", "w") as f:
        for fc, pkt in short_term_profile:
            f.write("{} & {} \\\\\n".format(fc, pkt))
        f.close()

    print(short_term_profile)
    return short_term_profile

def generate_slo_vio_signal_plot(core_snapshots, title=None):
    """ |core_snapshots| is a list of CoreSnapshot objects
        This function first seperates SLO-violating and non-SLO-violating epochs.
        THen, it calls |cluster_plot| function to generate node clusters in a plot.
    """
    slo_vio_nodes = []
    non_slo_vio_nodes = []
    for i in range(len(core_snapshots)):
        slo, non_slo = slo_violation_analysis(core_snapshots[i])
        slo_vio_nodes += slo
        non_slo_vio_nodes += non_slo

    short_profile = get_short_term_profile(slo_vio_nodes)
    # node_groups = [('x', 'blue', 1, slo_vio_nodes), ('.', 'purple', 1, non_slo_vio_nodes)]
    node_groups = [('x', 'blue', 1, short_profile)]

    cluster_plot(node_groups, "blue: SLO-vio epoch; purple: non SLO-vio epoch")
    if title:
        plt.savefig('slo_vio_signal%s.png' %(title), dpi=600)
    else:
        plt.savefig('slo_vio_signal.png', dpi=600)
    return

# Get the (packet count, active flow count) for both non-SLO-violated and SLO-violated epochs.
def slo_violation_analysis(snapshots):
    slo_vio_nodes = []
    non_slo_vio_nodes = []

    n = len(snapshots)
    for sidx in range(1, n-2):
        is_both = 0
        if snapshots[sidx]._slo_violations == 0:
            is_both += 1
            non_slo_vio_nodes.append((snapshots[sidx]._active_flow_cnt, snapshots[sidx]._pkt_processed))
        if snapshots[sidx]._slo_violations > 0:
            is_both += 1
            slo_vio_nodes.append((snapshots[sidx]._active_flow_cnt, snapshots[sidx]._pkt_processed))
            # slo_vio_nodes.append((snapshots[sidx]._active_flow_cnt, snapshots[sidx]._pkt_rate))

        # if snapshots[sidx]._slo_violations == 0 and snapshots[sidx+1]._slo_violations == 0 and snapshots[sidx+2]._slo_violations == 0:
        #     is_both += 1
        #     non_slo_vio_nodes.append((snapshots[sidx]._pkt_rate, snapshots[sidx]._active_flow_cnt))
        # if snapshots[sidx-1]._slo_violations >= 10 and snapshots[sidx]._slo_violations >= 10 and snapshots[sidx+1]._slo_violations >= 10:
        #     is_both += 1
        #     slo_vio_nodes.append((snapshots[sidx]._pkt_rate, snapshots[sidx]._active_flow_cnt))

        if is_both == 2:
            print("Error")

    return (slo_vio_nodes, non_slo_vio_nodes)


def main():
    target_cores = [1]
    core_snapshots = {}
    for core_id in target_cores:
        core_snapshots[core_id] = parse_core_snapshot(core_id)
    print("parse: finished")

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
    for core_id in target_cores:
        generate_slo_vio_signal_plot([core_snapshots[core_id]], "core%d" %(core_id))
    print("plot: finished")
    return

if __name__ == '__main__':
    main()
