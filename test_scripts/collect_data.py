'''
python collect_data.py

This script is used to run tests and collect data.
It has been designed to run the following pipeline:
fg-> timestamp -> port_out
port_in -> nfv_monitor -> bypass -> measure -> sink

The port out is looped back to port in. The entire pipeline
is present in hw_ts_test.bess file.

It collects stats from nfv_monitor and the measure module.
This data gets written to a file named "data"

This script can be used as a template to write more automations
and collect test data

The script uses bessctl to interact with bessd and collect data
by writing the output to files.
'''
import os
from time import sleep
import subprocess
import re

run_time = 10
reset_time = 5
pps_sample = [10000,50000,100000]
pcycle_sample = [200,2000, 20000, 200000]
num_runs = 3


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


def do_test(i,pps, pcycle):
    os.system("../bin/bessctl daemon stop")
    os.system("../bin/bessctl daemon start")
    with open("data", 'a') as f:
        f.write("Run %d --- params: pps=%d pcycle=%d\n"%(i, pps,pcycle))
    os.system("../bin/bessctl 'run samples/hw_ts_test BESS_PKT_SIZE=200,BESS_PKT_CYCLE="+str(pcycle)+",BESS_PKT_RATE="+str(pps)+"'")
    sleep(reset_time)
    os.system("../bin/bessctl 'command module nfv_monitor clear EmptyArg'")
    os.system("../bin/bessctl 'command module measure0 clear EmptyArg'")
    sleep(run_time)
    os.system("../bin/bessctl 'command module nfv_monitor get_summary EmptyArg'")
    os.system("../bin/bessctl 'command module measure0 get_summary MeasureCommandGetSummaryArg {\"latency_percentiles\":[50,99]}' > output")
    (out,err) = subprocess.Popen(["cat", "stats.txt"], stdout=subprocess.PIPE).communicate()
    hw_latency = get_hw_latency(out)
    (out,err) = subprocess.Popen(["cat", "output"], stdout=subprocess.PIPE).communicate()
    latency = get_pipline_latency(out)
    with open("data",'a') as f:
        f.write("%d,%d,%d,%d\n"%(hw_latency[0], latency[0], hw_latency[1], latency[1]))
    print(hw_latency, latency)

def run_test():
    with open("data",'a') as f:
        f.write("p50_hw, p50_measure, p99_hw, p99_measure\n")
    for pps in pps_sample:
        for pcycle in pcycle_sample:
            for i in range(num_runs):
                do_test(i,pps,pcycle)
            

def clear_system():
    os.system("rm -f stats.txt data output")
clear_system()
run_test()