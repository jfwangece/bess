#!/bin/bash
# This script sets up Hugepages and turns off ASLR

# For single-node systems
# sudo sysctl vm.nr_hugepages=4096

echo 4096 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 4096 | sudo tee /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages

echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

