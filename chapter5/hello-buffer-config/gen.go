package main

//go:generate go tool bpf2go -tags linux -cflags "-D __TARGET_ARCH_x86 -Wall -O2 -g" hello_buffer_config hello_buffer_config.bpf.c
