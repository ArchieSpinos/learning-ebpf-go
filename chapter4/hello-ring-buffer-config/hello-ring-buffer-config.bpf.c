//go:build ignore

#include <linux/types.h> 
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>

struct user_msg_t {
  char message[12];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);
  __type(value, struct user_msg_t);
} config SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
} output SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

struct data_t {     
    __u32 pid;
    __u32 uid;
   char command[16];
   char message[12];
};

SEC("ksyscall/execve")
int hello(void *ctx) {
  struct data_t data = {};
  struct user_msg_t *p;
  char message[12] = "Hello World";

  data.pid = bpf_get_current_pid_tgid() >> 32;
  data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

  bpf_get_current_comm(&data.command, sizeof(data.command));

  p = bpf_map_lookup_elem(&config, &data.uid); 
  if (p != 0) {
    bpf_probe_read_kernel(&data.message, sizeof(data.message), p->message);
  } else {
    bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
  }

  bpf_ringbuf_output(&output, &data, sizeof(data), 0);

  return 0;
}