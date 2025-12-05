//go:build ignore

#include "../../vmlinux.h"
#include <bpf/bpf_helpers.h>
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
    } events SEC(".maps");

struct event_t {
    char command[16];
    char filename[256];
    int dfd;
};

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_openat")
int capture_openat(struct trace_event_raw_sys_enter* ctx) {
    struct event_t event = {};
    event.dfd = (int)ctx->args[0];
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), (const void *)ctx->args[1]);
    bpf_get_current_comm(&event.command, sizeof(event.command));
    bpf_ringbuf_output(&events, &event, sizeof(event), 0);
    return 0;
}