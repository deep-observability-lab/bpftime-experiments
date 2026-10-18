#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "uprobe.h"

#define NORD_ETH_P_IP 0x0008
#define DATA_OFF_OFFSET 16
#define EHTERTYPE_OFFSET 12
#define PROTO_OFFSET 23
#define SADDR_OFFSET 26
#define DADDR_OFFSET 30
#define SPORT_OFFSET 34
#define DPORT_OFFSET 36

struct flow {
    __u8   proto;
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
};

struct tstate {
    __u32 depth;   // how many probed calls this thread has open right now
    __u64 bits;    // bit i = 1 means the call at depth i passed the filter
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct flow);
} target SEC(".maps");

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
    __uint(max_entries, 1024);
    __type(key, __u64);            // thread id
    __type(value, struct tstate);  // that thread's record
} tstates SEC(".maps");

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

    return 1;   // every check passed
}

SEC("uprobe")
int do_uprobe(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    struct tstate *ts = bpf_map_lookup_elem(&tstates, &tid);
    if (!ts) {
        struct tstate zero = {0};
        bpf_map_update_elem(&tstates, &tid, &zero, BPF_NOEXIST);
        ts = bpf_map_lookup_elem(&tstates, &tid);
        if (!ts) return 0;
    }

    __u32 d = ts->depth;
    ts->depth = d + 1;              // every entry goes one level deeper
    if (d >= 64) return 0;          // too deep, bits has only 64 slots

    if (!match(ctx)) {              // filter failed
        ts->bits &= ~(1ULL << d);   // mark this level as "not traced"
        return 0;
    }
    ts->bits |= (1ULL << d);        // mark this level as "traced"

    // added LSB specifies entry (0) or exit (1)
    __u32 key = (__u32)(PT_REGS_IP(ctx) << 1);
    __u64 init = 1, *val = bpf_map_lookup_elem(&counters, &key);
    if (val) (*val)++;
    else bpf_map_update_elem(&counters, &key, &init, BPF_ANY);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}

SEC("uretprobe")
int do_uretprobe(struct pt_regs *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    struct tstate *ts = bpf_map_lookup_elem(&tstates, &tid);
    if (!ts || ts->depth == 0) return 0;   // no matching entry, so ignore

    __u32 d = ts->depth - 1;               // the level this call was entered at
    ts->depth = d;                         // go back up one level
    if (d >= 64) return 0;
    if (!(ts->bits & (1ULL << d))) return 0;   // its entry was filtered out, drop

    __u32 key = (__u32)((PT_REGS_IP(ctx) << 1) | 1);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
