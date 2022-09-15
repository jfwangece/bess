import os
import sys
import numpy as np

def read_epoch_log(file_name):
    packet_counters = []
    with open(file_name) as f:
        lines = f.readlines()
        for line in lines:
            if "short-term:" not in line:
                continue
            data_line = line[line.find("short-term:") + len("short-term:"):].strip()
            nums = [0, 0, 0, 0, 0]
            for x in data_line.split(","):
                num_str = x.strip()
                if "core" in num_str:
                    num = int(num_str[num_str.find("core") + len("core"):])
                    nums[0] = num
                    continue
                elif "ct=" in num_str:
                    num = int(num_str[num_str.find("ct=") + len("ct="):])
                    nums[1] = num
                    continue
                elif "d1=" in num_str:
                    num = int(num_str[num_str.find("d1=") + len("d1="):])
                    nums[2] = num
                    continue
                elif "d2=" in num_str:
                    num = int(num_str[num_str.find("d2=") + len("d2="):])
                    nums[3] = num
                    continue
                elif "d3=" in num_str:
                    num = int(num_str[num_str.find("d3=") + len("d3="):])
                    nums[4] = num
                    continue
                else:
                    continue
            packet_counters.append(nums)
        f.close()
    return packet_counters

def do_analysis(file_name):
    epoch_data = read_epoch_log(file_name)
    cores = set()
    num_arrivals = 0
    drop_type1 = 0
    max_drop_type1 = 0
    drop_type2 = 0
    drop_type3 = 0
    for data in epoch_data:
        cores.add(data[0])
        num_arrivals += data[1]
        drop_type1 += data[2]
        max_drop_type1 = max(max_drop_type1, data[2])
        drop_type2 += data[3]
        drop_type3 += data[4]

    total_samples = len(epoch_data)
    total_epochs = total_samples / len(cores)
    total_exp_seconds = total_epochs * 100 / 1000000
    print("Exp time: %d (seconds)" %(total_exp_seconds))
    print("# of normal cores: %d" %(len(cores)))
    print("# of (short) epochs: %d" %(total_epochs))
    print("arrivals: %d; drop1: %d; drop2: %d; drop3: %d" \
        %(num_arrivals, drop_type1, drop_type2, drop_type3))
    print("avg drop1: %f" %(drop_type1 * 1.0 / total_samples))
    print("max drop1: %d" %(max_drop_type1))
    return

def main():
    if len(sys.argv) == 1:
        print("usage: python profile_plot.py <profile-filename>")
        return
    file_name = sys.argv[1]
    do_analysis(file_name)
    return

if __name__ == "__main__":
    main()
