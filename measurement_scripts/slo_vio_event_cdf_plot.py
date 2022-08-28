#!/usr/bin/env python
import sys
import math
import numpy as np
import matplotlib
matplotlib.use('TkAgg', force=True)
import matplotlib.pyplot as plt
from utils import CoreSnapshot, SLOEvent
from utils import read_core_snapshot

stats_dir = "../stats_0314/"

def cdf_plot(x_data, title=None):
    _, ax = plt.subplots()

    sorted_x_data = sorted(x_data)
    n = len(sorted_x_data)
    y_pos = np.arange(n) / float(n - 1)

    ax.plot(sorted_x_data, y_pos, marker='.', color='purple')
    ax.set_xlabel("Epochs")
    ax.set_ylabel("Percentile (%)")
    if title:
        ax.set_title(title)
    plt.grid(True)

def get_percentile(p_val, x_data):
    if len(x_data) < 100:
        return "Na (not enough samples)"
    if p_val < 0 or p_val > 100:
        return "Na (p val out of range)"

    sorted_x_data = sorted(x_data)
    n = len(sorted_x_data)
    p_pos = int(p_val * (n - 1) / 100)
    return sorted_x_data[p_pos]

def parse_core_snapshot(core_id):
    stats_filename = "stats%d.txt" %(core_id)
    stats_abs_dir = stats_dir + stats_filename
    snapshots = read_core_snapshot(stats_abs_dir)
    return snapshots

def generate_epoch_distribution_plot(slo_events, title):
    epochs = [se._epoch_cnt for se in slo_events]
    cdf_plot(epochs, title)
    plt.savefig('slo_vio_epoch_dist_%s.png' %(title), dpi=600)


# Get SLO-violation events.
def stats_analysis(snapshots):
    short_term_slo_vio = []
    long_term_slo_vio = []
    # Count short/long-term SLO violation
    total_pkts = 0
    epoch_with_slo_vio = 0
    pkt_with_slo_vio = 0
    for s in snapshots:
        total_pkts += s._pkt_rate
        if s._slo_violations > 0:
            epoch_with_slo_vio += 1
            pkt_with_slo_vio += s._slo_violations
        else:
            if epoch_with_slo_vio >= 1:
                e = SLOEvent(epoch_with_slo_vio, pkt_with_slo_vio)
                if epoch_with_slo_vio >= 20:
                    long_term_slo_vio.append(e)
                elif epoch_with_slo_vio < 20:
                    short_term_slo_vio.append(e)

            epoch_with_slo_vio = 0
            pkt_with_slo_vio = 0

    print("Total epochs: %d" %(len(snapshots)))
    print("Short term SLO violations: %d" %(len(short_term_slo_vio)))
    print("Long term SLO violations: %d" %(len(long_term_slo_vio)))
    return (total_pkts, len(snapshots), short_term_slo_vio, long_term_slo_vio)


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

    # SLO-event statistics
    per_core_results = [None]
    for i in range(1, 8):
        print("Core %d statistics analysis:" %(i))
        per_core_results.append(stats_analysis(core_snapshots[i]))
        total_pkts += per_core_results[i][0]
        total_epochs += per_core_results[i][1]
        short_term_slo_vio += per_core_results[i][2]
        long_term_slo_vio += per_core_results[i][3]

    all_slo_vio = short_term_slo_vio + long_term_slo_vio

    for x in short_term_slo_vio:
        if x:
            short_term_slo_vio_epochs += x._epoch_cnt
            short_term_slo_vio_pkts += x._pkt_cnt
    for x in long_term_slo_vio:
        if x:
            long_term_slo_vio_epochs += x._epoch_cnt
            long_term_slo_vio_pkts += x._pkt_cnt

    short_term_slo_vio_epoch_ratio = short_term_slo_vio_epochs * 100 / total_epochs
    short_term_slo_vio_pkt_ratio = short_term_slo_vio_pkts * 100 / total_pkts
    long_term_slo_vio_epoch_ratio = long_term_slo_vio_epochs * 100 / total_epochs
    long_term_slo_vio_pkt_ratio = long_term_slo_vio_pkts * 100 / total_pkts

    print("-" * 84)
    print("Cluster-scale analysis:")
    print("Total epochs: %d" %(total_epochs))
    print("Total pkts: %d" %(total_pkts))
    print("Short term SLO violations:")
    print(" - cnt=%d; epochs=%d [%.2f%%]; pkts=%d [%.2f%%]" \
        %(len(short_term_slo_vio), short_term_slo_vio_epochs, short_term_slo_vio_epoch_ratio, \
        short_term_slo_vio_pkts, short_term_slo_vio_pkt_ratio))
    print("Long term SLO violations:")
    print(" - cnt=%d; epochs=%d [%.2f%%]; pkts=%d [%.2f%%]" %(len(long_term_slo_vio), long_term_slo_vio_epochs, long_term_slo_vio_epoch_ratio, \
        long_term_slo_vio_pkts, long_term_slo_vio_pkt_ratio))

    # SLO-violating event plots
    generate_epoch_distribution_plot(short_term_slo_vio, "short")
    generate_epoch_distribution_plot(long_term_slo_vio, "long")
    generate_epoch_distribution_plot(short_term_slo_vio + long_term_slo_vio, "Epoch distribution of SLO violation events")

    # Percentiles of SLO-violating events' duration
    slo_vio_event_epochs = [ss._epoch_cnt for ss in all_slo_vio]

    print(get_percentile(90, slo_vio_event_epochs))
    print(get_percentile(95, slo_vio_event_epochs))
    print(get_percentile(99, slo_vio_event_epochs))

    return

if __name__ == '__main__':
    main()
