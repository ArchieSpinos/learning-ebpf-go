typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;

typedef signed char        __s8;
typedef short              __s16;
typedef int                __s32;
typedef long long          __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;

typedef __u16 __sum16;
typedef __u32 __wsum;

#define __TARGET_ARCH_x86
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/hello")
int hello(struct pt_regs *ctx)
{
    bpf_printk("Hello World!\n");
    return 0;
}