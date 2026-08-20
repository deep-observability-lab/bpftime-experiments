#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "uprobe.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, FUNC);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u32);
} events SEC(".maps");

SEC("uprobe")
int do_uprobe(struct pt_regs *ctx) {
    // added LSB specifies entry (0) or exit (1)
    __u32 key = (__u32)(PT_REGS_IP(ctx) << 1);
    __u64 init = 1;
    __u64 *val = bpf_map_lookup_elem(&counters, &key);
    if (val) (*val)++;
    else bpf_map_update_elem(&counters, &key, &init, BPF_ANY);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}

SEC("uretprobe")
int do_uretprobe(struct pt_regs *ctx) {
    __u32 key = (__u32)((PT_REGS_IP(ctx) << 1) | 1);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
