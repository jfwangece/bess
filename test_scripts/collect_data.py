import os
from time import sleep
import subprocess
import re

run_time = 10
reset_time = 5
pps_sample = [10000,50000,100000]
pcycle_sample = [20,200,2000]
num_runs = 3


def get_hw_latency(text):
    pat = re.findall("P99 latency:.*", text)[0]
    pat = pat.split(':')[-1]
    return float(pat)

def get_pipline_latency(text):
    pat = re.findall("percentile_values_ns:.*", text)[0]
    pat = pat.split(':')[-1]
    return float(pat)


def do_test(i,pps, pcycle):
    with open("data", 'a') as f:
        f.write("Run %d --- params: pps=%d pcycle=%d\n"%(i, pps,pcycle))
    os.system("../bin/bessctl 'run samples/hw_ts_test BESS_PKT_SIZE=200,BESS_PKT_CYCLE="+str(pcycle)+",BESS_PKT_RATE="+str(pps)+"'")
    sleep(reset_time)
    os.system("../bin/bessctl 'command module nfv_monitor clear EmptyArg'")
    os.system("../bin/bessctl 'command module measure0 clear EmptyArg'")
    sleep(run_time)
    os.system("../bin/bessctl 'command module nfv_monitor get_summary EmptyArg'")
    os.system("../bin/bessctl 'command module measure0 get_summary MeasureCommandGetSummaryArg {\"latency_percentiles\":[99]}' > output")
    (out,err) = subprocess.Popen(["cat", "../stats.txt"], stdout=subprocess.PIPE).communicate()
    hw_latency = get_hw_latency(out)
    (out,err) = subprocess.Popen(["cat", "output"], stdout=subprocess.PIPE).communicate()
    latency = get_pipline_latency(out)
    with open("data",'a') as f:
        f.write("%d,%d\n"%(hw_latency, latency))
    print(hw_latency, latency)

def run_test():
    for pps in pps_sample:
        for pcycle in pcycle_sample:
            for i in range(num_runs):
                do_test(i,pps,pcycle)
            

def clear_system():
    os.system("rm -f ../stats.txt data output")
clear_system()
run_test()