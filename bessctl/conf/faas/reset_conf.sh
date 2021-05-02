#!/bin/bash

# flowgen2
sed -i 's/core_offset = 1/core_offset = 8/g' $(find . -type f -name "flowgen2_*.bess")

sed -i "s/pcie_addr = ['06:00.0', '06:00.1']/pcie_addr = ['81:00.0', '81:00.1']/g" $(find . -type f -name "flowgen2_*.bess")

# faas_ingres

sed -i "s/pcie0 = '06:00.0'/pcie0 = '81:00.0'/g" $(find . -type f -name "faas_ingress*.bess")
sed -i "s/faas_ip = '128.105.145.252'/faas_ip = '128.105.145.172'/g" $(find . -type f -name "faas_ingress*.bess")
sed -i "s/redis_ip = '128.105.145.181'/redis_ip = '128.105.145.181'/g" $(find . -type f -name "faas_ingress*.bess")
