//go:build ignore

#include "../../bpf/common/bpf_types.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32); 
} events SEC(".maps");

struct data_t {     
   int pid;
   int uid;
   char command[16];
   char message[12];
};

char LICENSE[] SEC("license") = "GPL";

SEC("ksyscall/execve")
int hello(void *ctx) {
   struct data_t data = {}; 
   char message[12] = "Hello World";
 
   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   
   bpf_get_current_comm(&data.command, sizeof(data.command));
   bpf_probe_read_kernel(&data.message, sizeof(data.message), message); 
 
   bpf_perf_event_output(ctx, &events, 0, &data, sizeof(data));
   return 0;
}