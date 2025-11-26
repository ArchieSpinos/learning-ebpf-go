#include "../../../bpf/common/bpf_types.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/hello")
int hello(struct pt_regs *ctx)
// {
//     uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
//     p = counter_table.lookup(&uid);
//     counter++;
//     counter_table.update(&uid, &counter);
//     return 0;
// }