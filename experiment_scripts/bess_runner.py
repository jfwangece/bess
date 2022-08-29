# This script is used to run tests and collect data.
# It has been designed to run the following pipeline:
# fg-> timestamp -> port_out
# port_in -> nfv_monitor -> bypass -> measure -> sink
# The port out is looped back to port in. The entire pipeline
# is present in hw_ts_test.bess file.
# It collects stats from nfv_monitor and the measure module.
# This data gets written to a file named "data"
# This script can be used as a template to write more automations
# and collect test data
# The script uses bessctl to interact with bessd and collect data
# by writing the output to files.
#
# To run the script, do the following:
# python collect_data.py

import os
from time import sleep
from datetime import datetime
import subprocess
import re

BESS_DIR = subprocess.check_output(["git", "rev-parse", "--show-toplevel"])[:-1]
BESS_DIR = os.path.abspath(BESS_DIR) + "/"
BESSCTL_DIR = BESS_DIR + "bin/bessctl"

EXP_INIT_TIME_SEC = 3
EXP_RUN_TIME_SEC = 7
num_runs = 1

LATENCY_PERCENTILES = [50, 75, 90, 95, 99]
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

def run_experiment_once(bess_script, pkt_size, pkt_rate, flow_count):
    os.system(BESSCTL_DIR + " daemon stop")
    os.system(BESSCTL_DIR + " daemon start")
    os.system(BESSCTL_DIR + " 'run %s BESS_PKT_SIZE=%d,BESS_PKT_RATE=%s,BESS_FLOW=%s'" %(bess_script, pkt_size, pkt_rate, flow_count))
    # Skip the startup process
    sleep(EXP_INIT_TIME_SEC)
    # os.system(BESSCTL_DIR + " 'command module nfv_monitor clear EmptyArg'")
    os.system(BESSCTL_DIR + " 'command module measure0 clear EmptyArg'")
    # Run for a while
    sleep(EXP_RUN_TIME_SEC)
    # os.system(BESSCTL_DIR + " 'command module nfv_monitor get_summary EmptyArg'")
    os.system(BESSCTL_DIR + " 'command module measure0 get_summary MeasureCommandGetSummaryArg {\"latency_percentiles\":[50,75,90,95,99]}' > output")
    # Get results
    # (out, err) = subprocess.Popen(["cat", "stats.txt"], stdout=subprocess.PIPE).communicate()
    # hw_latency = get_hw_latency(out)
    (out, err) = subprocess.Popen(["cat", "output"], stdout=subprocess.PIPE).communicate()
    latency = get_pipline_latency(out)
    return latency

def run_test(bess_script, pkt_sizes, pkt_rates, flow_counts):
    t1 = datetime.now()

    input_tags = ["pkt_size", "pkt_rate", "flow_cnt"]
    latency_percentile_tags = ["P%d" %(x) for x in LATENCY_PERCENTILES]
    with open(output_fname,'a') as f:
        f.write("Results for %s\n\n" %(bess_script))
        for tag in input_tags + latency_percentile_tags:
            f.write("{0: <12}".format(tag))
        f.write("\n")

        curr_round = 1
        total_rounds = len(pkt_sizes) * len(pkt_rates) * len(flow_counts)
        print("Total rounds: {}".format(total_rounds))
        print("Exp loop begins ..")
        for pkt_size in pkt_sizes:
            for pkt_rate in pkt_rates:
                for flow_count in flow_counts:
                    print("Round %d" %(curr_round))
                    curr_round += 1
                    for i in range(num_runs):
                        print(pkt_size, pkt_rate, flow_count)
                        curr_result = run_experiment_once(bess_script, pkt_size, pkt_rate, flow_count)
                        if len(curr_result) != len(LATENCY_PERCENTILES):
                            continue
                        f.write("{0: <12}{1: <12}{2: <12}".format(pkt_size, pkt_rate, flow_count))
                        for num in curr_result:
                            f.write("{0: <12}".format(num))
                        f.write("\n")
        print("Exp loop ends ..")
        f.close()

    t2 = datetime.now()
    print("NF profiler finished! Total runtime: {}.".format(t2 - t1))
    return

def clear_system():
    for f in OUTPUT_FILES:
        os.system("rm -f %s" %(f))

if __name__ == "__main__":
    # Clean all previous intermediate/output files.
    clear_system()
    # Run tests
    run_test("nfvctrl/profile_chain4", [1000, 1400], [1000000], [1000])
