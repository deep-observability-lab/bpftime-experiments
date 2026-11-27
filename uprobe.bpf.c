#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "uprobe.h"

#define NORD_ETH_P_IP    0x0008
#define DATA_OFF_OFFSET  16
#define EHTERTYPE_OFFSET 12
#define PROTO_OFFSET     23
#define SADDR_OFFSET     26
#define DADDR_OFFSET     30
#define SPORT_OFFSET     34
#define DPORT_OFFSET     36

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct flow);
} target SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} sthresh SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, FUNC);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 32); // placeholder, will be updated by userspace
    __type(key, __u32);
    __type(value, __u32);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DEPTH);
    __type(key, __u64);
    __type(value, __u32);
} depths SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct path_key);
    __type(value, __u64);
} paths SEC(".maps");

static __always_inline void save_path(struct pt_regs *ctx) {
    struct path_key k;
    __builtin_memset(&k, 0, sizeof(k));
    k.leaf = PT_REGS_IP(ctx);

    __u64 ra = 0;
    __u64 fp = PT_REGS_FP(ctx);
    if (bpf_probe_read_user(&ra, sizeof(ra), (void *)PT_REGS_SP(ctx)) == 0 && ra != 0) {
        k.frame[0] = ra;
        k.nframes = 1;

#pragma unroll
        for (int i = 1; i < STACK_FRAMES; i++) {
            __u64 next_fp = 0, next_ra = 0;
            if (fp == 0)
                break;
            if (bpf_probe_read_user(&next_ra, sizeof(next_ra), (void *)(fp + 8)) != 0)
                break;
            if (bpf_probe_read_user(&next_fp, sizeof(next_fp), (void *)fp) != 0)
                break;
            if (next_ra == 0 || next_fp <= fp)
                break;
            k.frame[i] = next_ra;
            k.nframes = i + 1;
            fp = next_fp;
        }
    }

    __u64 init = 1, *val = bpf_map_lookup_elem(&paths, &k);
    if (val) (*val)++;
    else bpf_map_update_elem(&paths, &k, &init, BPF_ANY);
}

static __always_inline int match(struct pt_regs *ctx) {
    __u8 *mbuf = (__u8 *)PT_REGS_PARM1(ctx), *buf_addr, *pkt, proto;
    if (!mbuf) return 0;

    if (bpf_probe_read_user(&buf_addr, sizeof(buf_addr), mbuf) != 0) return 0;
    if (!buf_addr) return 0;

    __u16 data_off;
    if (bpf_probe_read_user(&data_off, sizeof(data_off), mbuf + DATA_OFF_OFFSET) != 0) return 0;
    pkt = buf_addr + data_off;

    __be16 ethertype, sport, dport;
    if (bpf_probe_read_user(&ethertype, sizeof(ethertype), pkt + EHTERTYPE_OFFSET) != 0) return 0;
    if (ethertype != NORD_ETH_P_IP) return 0;

    __u32 key = 0;
    struct flow *tf = bpf_map_lookup_elem(&target, &key);
    if (!tf) return 0;

    if (bpf_probe_read_user(&proto, sizeof(proto), pkt + PROTO_OFFSET) != 0) return 0;
    if (tf->proto != 0 && proto != tf->proto) return 0;

    __be32 saddr, daddr;
    if (bpf_probe_read_user(&saddr, sizeof(saddr), pkt + SADDR_OFFSET) != 0) return 0;
    if (tf->saddr != 0 && saddr != tf->saddr) return 0;

    if (bpf_probe_read_user(&daddr, sizeof(daddr), pkt + DADDR_OFFSET) != 0) return 0;
    if (tf->daddr != 0 && daddr != tf->daddr) return 0;

    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        if (bpf_probe_read_user(&sport, sizeof(sport), pkt + SPORT_OFFSET) != 0) return 0;
        if (tf->sport != 0 && sport != tf->sport) return 0;

        if (bpf_probe_read_user(&dport, sizeof(dport), pkt + DPORT_OFFSET) != 0) return 0;
        if (tf->dport != 0 && dport != tf->dport) return 0;
    }

    return 1;
}

SEC("uprobe")
int do_uprobe_match(struct pt_regs *ctx) {
    save_path(ctx);
    if (!match(ctx)) return 0;

    const __u32 zkey = 0;
    const __u32 *sth = bpf_map_lookup_elem(&sthresh, &zkey);
    if (sth)
        if (*sth != 0 && bpf_get_prandom_u32() >= *sth) return 0;

    // added LSB specifies entry (0) or exit (1)
    const __u32 key = (__u32)(PT_REGS_IP(ctx) << 1);
    __u64 init = 1, *val = bpf_map_lookup_elem(&counters, &key);
    if (val) (*val)++;
    else bpf_map_update_elem(&counters, &key, &init, BPF_ANY);

    __u64 tid = bpf_get_current_pid_tgid();
    __u32 *dp = bpf_map_lookup_elem(&depths, &tid);
    if (!dp) {
        __u32 init = 0;
        bpf_map_update_elem(&depths, &tid, &init, BPF_NOEXIST);
        dp = bpf_map_lookup_elem(&depths, &tid);
        if (!dp) return 0;
    }

    (*dp)++; // advance one level deeper, this also enables tracing for later uprobes

    __u64 t = bpf_ktime_get_ns();
    __u32 ev[3] = { key, (__u32)t, (__u32)(t >> 32) };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, ev, sizeof(ev));
    return 0;
}

SEC("uprobe")
int do_uprobe(struct pt_regs *ctx) {
    save_path(ctx);
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 *dp = bpf_map_lookup_elem(&depths, &tid);
    if (!dp || *dp == 0) return 0; // no flow matched

    __u32 d = *dp;
    if (d > MAX_DEPTH) return 0;
    (*dp)++;

    __u32 key = (__u32)(PT_REGS_IP(ctx) << 1);
    __u64 init = 1, *val = bpf_map_lookup_elem(&counters, &key);
    if (val) (*val)++;
    else bpf_map_update_elem(&counters, &key, &init, BPF_ANY);

    __u64 t = bpf_ktime_get_ns();
    __u32 ev[3] = { key, (__u32)t, (__u32)(t >> 32) };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, ev, sizeof(ev));
    return 0;
}

SEC("uretprobe")
int do_uretprobe(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 *dp = bpf_map_lookup_elem(&depths, &tid);
    if (!dp || *dp == 0) return 0;

    __u32 d = *dp;
    if (d == 0 || d > MAX_DEPTH) return 0;
    (*dp)--; // retreat one level

    __u32 key = (__u32)((PT_REGS_IP(ctx) << 1) | 1);
    __u64 t = bpf_ktime_get_ns();
    __u32 ev[3] = { key, (__u32)t, (__u32)(t >> 32) };
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, ev, sizeof(ev));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
