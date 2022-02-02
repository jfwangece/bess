#!/usr/bin/env python
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt

# Cluster CPU core usage information
class Snapshot(object):
    def __init__(self, core, rate):
        self._core_cnt = core
        self._pkt_rate = rate

def data_reader(file_name):
    cluster_snapshots = []
    with open(file_name) as f:
        lines = f.readlines()
        for line in lines:
            if not ('core' in line and 'rate' in line):
                continue

            data = [float(m.split(':')[1]) for m in line.split(',')]
            ss = Snapshot(data[0], data[1])
            cluster_snapshots.append(ss)
        f.close()
    return cluster_snapshots

# |y_data| is an list of tuple (data, color).
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
        ax.plot(x_data, y_data, lw=1.0, color=y_color, alpha=1)

    if yscale_log == True:
        ax.set_yscale('log')
    ax.set_title(title)
    ax.set_xlabel(x_label)
    ax.set_ylabel(y_label)
    plt.grid(True)


def main():
    per_core_rate = 680000 * 0.85
    snapshots = data_reader('stats.txt')
    x = [i for i in range(len(snapshots))]
    y1 = [s._core_cnt for s in snapshots]
    #y2 = []

    scatter_group_curve_plot(x, [(y1, 'b')], "Epoch", "Core #", "Timeline of CPU core usage", False)
    plt.show()
    return

if __name__ == '__main__':
    main()
