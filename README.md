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
![image](https://github.com/user-attachments/assets/21c9a2f9-ce62-48a3-a84f-e6b41090084b)








