//go:build ignore

#include "../../bpf/common/bpf_types.h"
#include <bpf/bpf_helpers.h>

#define __TARGET_ARCH_x86

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/hello")
int hello(struct pt_regs *ctx)
{
    bpf_printk("Hello World!\n");
    return 0;
}