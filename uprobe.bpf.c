#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "uprobe.h"

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, FUNCS);
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
    struct event e = {};
    e.key = (__u32)bpf_get_attach_cookie(ctx);
    __u64 *val = bpf_map_lookup_elem(&counters, &e.key);
    if (val) (*val)++;
    e.is_exit = 0;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

SEC("uretprobe")
int do_uretprobe(struct pt_regs *ctx)
{
    struct event e = {};
    e.key = (__u32)bpf_get_attach_cookie(ctx);
    e.is_exit = 1;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
