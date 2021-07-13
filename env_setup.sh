#!/bin/bash
# This script sets up Hugepages and turns off ASLR

# For single-node systems
# sudo sysctl vm.nr_hugepages=1024

echo 1024 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 1024 | sudo tee /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages

echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

