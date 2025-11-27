//go:build ignore

#include "../../bpf/common/bpf_types.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} counter_table SEC(".maps");


char LICENSE[] SEC("license") = "GPL";

SEC("raw_tracepoint/sys_enter")
int hello(void *ctx) {
    __u32 uid;
    __u64 counter = 0;
    __u64 *p;
 
    uid = (__u32)(bpf_get_current_uid_gid());;
    p = bpf_map_lookup_elem(&counter_table, &uid); 
    if (p != 0) {
       counter = *p;
    }
    counter++;
    bpf_map_update_elem (&counter_table, &uid, &counter, BPF_ANY);
    return 0;
 }
