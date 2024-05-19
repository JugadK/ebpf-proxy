#!/bin/bash

clang -O2 -g -Wall -target bpf -c ebpf/ebpf_proxy.ebpf.c -o ebpf/ebpf_proxy.ebpf.o
#ip link set wlan0 xdpgeneric obj ebpf_proxy.ebpf.o sec xdp

