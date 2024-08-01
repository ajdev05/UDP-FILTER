# XDP UDP FILTER

This program filters and drops UDP packets that exceed certain thresholds to prevent UDP based DDoS Attacks. It tracks the number and size of packets from each source, dropping packets if they exceed predefined limits.

## Dependencies:
```
sudo apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential
sudo apt install linux-tools-$(uname -r)
sudo apt install linux-headers-$(uname -r)
sudo apt install linux-tools-common linux-tools-generic
sudo apt install libbpf-dev
```

## Compile
```
clang -Wall -O2 -target bpf -c udpFilter.c -o udpFilter.o
```

## Hook the program up to the NIC

*EG: sudo ip link set dev [interface name] xdp obj udpFilter.o sec udpFilter*

```
sudo ip link set dev eth0 xdp obj udpFilter.o sec udpFilter
```


## Test Server Info
*To avoid errors for eBPF dependencies, please use Ubuntu 20.04.6*
![image](https://github.com/user-attachments/assets/e5a569b8-bd1c-4105-b1da-dd66b954d0b6)









