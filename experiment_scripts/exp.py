# This script is used to deploy a BESS chain.
#
# To run the script, do the following:
# python exp.py chain4

import os
import sys
from time import sleep
from datetime import datetime
import subprocess
import re

BESS_DIR = subprocess.check_output(["git", "rev-parse", "--show-toplevel"])[:-1]
BESS_DIR = os.path.abspath(BESS_DIR) + "/"
BESSCTL_DIR = BESS_DIR + "bin/bessctl"

EXP_INIT_TIME_SEC = 5
EXP_RUN_TIME_SEC = 25
num_runs = 1

# LATENCY_PERCENTILES = [50, 75, 90, 95, 99]
LATENCY_PERCENTILES = range(100)
output_fname = datetime.now().strftime('%Y-%m-%d-%H%M%S') + ".dat"
OUTPUT_FILES = ["*.dat"]

def get_hw_latency(text):
    latency = []
    pat = re.findall("P50 latency:.*", text)[0]
    pat = pat.split(':')[-1]
    latency.append(float(pat))
    pat = re.findall("P99 latency:.*", text)[0]
    pat = pat.split(':')[-1]
    latency.append(float(pat))
    return latency

def get_pipline_latency(text):
    pat = re.findall("percentile_values_ns:.*", text)
    latency = [float(x.split(':')[-1]) for x in pat]
    return latency

def run_bess_pipeline(bess_script):
    os.system(BESSCTL_DIR + " daemon stop")
    os.system(BESSCTL_DIR + " daemon start")
    os.system(BESSCTL_DIR + " 'run %s'" %(bess_script))
    return

def main():
    # Deploy a chain
    if len(sys.argv) != 2:
        print("usage: python exp.py <chain2/4>")
        return

    if sys.argv[1] == "chain2":
        run_bess_pipeline("nfvctrl/chain2")
    elif sys.argv[1] == "chain4":
        run_bess_pipeline("nfvctrl/chain4_mc_rss_monitor")
    else:
        print("%s is not supported" %(sys.argv[1]))

if __name__ == "__main__":
    main()
