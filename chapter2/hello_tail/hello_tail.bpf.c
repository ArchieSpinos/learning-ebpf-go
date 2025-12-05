//go:build ignore

#include "../../vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 300);
    __type(key, __u32);
    __type(value, __u32);
} syscall SEC(".maps");

char _license[] SEC("license") = "GPL";

SEC("raw_tracepoint/sys_enter")
int hello(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = ctx->args[1];
    bpf_tail_call(ctx,  &syscall, opcode);
    bpf_printk("Another syscall: %d\n", opcode);
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int hello_exec(void *ctx) {
    bpf_printk("Executing a program\n");
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = ctx->args[1];
    switch (opcode) {
        case 222:
            bpf_printk("Creating a timer\n");
            break;
        case 226:
            bpf_printk("Deleting a timer\n");
            break;
        default:
            bpf_printk("Some other timer operation (opcode=%d)\n", opcode);
            break;
        }
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int ignore_opcode(void *ctx) {
    return 0;
}

