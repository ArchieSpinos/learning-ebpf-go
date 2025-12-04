package main

//go:generate go tool bpf2go -tags linux hello_file_ring_buffer hello_file_ring_buffer.bpf.c
