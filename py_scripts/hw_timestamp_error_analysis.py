#!/usr/bin/env python
import sys
import math
import numpy as np
from utils import CoreSnapshot, SLOEvent
from utils import read_core_snapshot

stats_dir = "../stats_0314/"

def parse_core_snapshot(core_id):
    stats_filename = "stats%d.txt" %(core_id)
    stats_abs_dir = stats_dir + stats_filename
    snapshots = read_core_snapshot(stats_abs_dir)
    return snapshots

def hw_ts_error_analysis(snapshots):
    total_epochs = len(snapshots)
    total_pkts = 0
    total_epochs_w_ts_error = 0
    total_pkts_w_ts_error = 0
    for s in snapshots:
        total_pkts += s._pkt_rate
        if s._delay_errors >= 1:
            total_epochs_w_ts_error += 1
            total_pkts_w_ts_error += s._delay_errors

    print("Total epochs: %d; Total pkts: %d" %(total_epochs, total_pkts))
    print("Epochs with hw ts error: %d [%.2f%%]" %(total_epochs_w_ts_error, total_epochs_w_ts_error * 100.0 / total_epochs))
    print("Pkts with hw ts error: %d [%.2f%%]" %(total_pkts_w_ts_error, total_pkts_w_ts_error * 100.0 / total_pkts))
    return

def main():
    core_snapshots = []
    for core_id in range(9):
        core_snapshots.append(parse_core_snapshot(core_id))

    for i in range(9):
        print("Core %d hw timestamp error analysis:" %(i))
        hw_ts_error_analysis(core_snapshots[i])

    return

if __name__ == '__main__':
    main()
