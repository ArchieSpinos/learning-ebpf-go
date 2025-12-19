package main

//go:generate go tool bpf2go -tags linux -cflags "-O2 -g" hello_buffer_config hello-buffer-config.bpf.c
