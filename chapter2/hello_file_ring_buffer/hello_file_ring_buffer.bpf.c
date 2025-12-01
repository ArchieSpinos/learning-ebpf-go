//go:build ignore

#include "../../vmlinux.h"
#include <linux/types.h> 
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32); 
} events SEC(".maps");

struct event_t {
    char command[16];
    char filename[256];
    int dfd;

};

enum {
    false = 0,
    true = 1,
};


char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_openat")
int capture_openat(struct sys_enter_openat_args* ctx) {
    struct event_t event = {};



}