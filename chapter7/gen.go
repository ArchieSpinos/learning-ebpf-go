package main

//go:generate go tool bpf2go -tags linux -cflags "-D __TARGET_ARCH_x86 -D __BPF_TRACING__ -Wall -O2 -g" hello hello.bpf.c
