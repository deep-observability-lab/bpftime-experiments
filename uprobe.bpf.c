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
    // __u8 * for pointer arithmetic
    __u8 *mbuf = (__u8 *)PT_REGS_PARM1(ctx), *buf_addr, *pkt, proto;
    if (!mbuf) return 0;
    if (bpf_probe_read_user(&buf_addr, sizeof(buf_addr), mbuf)) return 0;
    if (!buf_addr) return 0;
    __u16 data_off, ethertype, sport, dport;
    if (bpf_probe_read_user(&data_off, sizeof(data_off), mbuf + DATA_OFF_OFFSET)) return 0;
    pkt = buf_addr + data_off;
    if (bpf_probe_read_user(&ethertype, sizeof(ethertype), pkt + EHTERTYPE_OFFSET)) return 0;
    if (ethertype != NORD_ETH_P_IP) return 0;
    if (bpf_probe_read_user(&proto, sizeof(proto), pkt + PROTO_OFFSET)) return 0;
    __u32 saddr, daddr;
    if (bpf_probe_read_user(&saddr, sizeof(saddr), pkt + SADDR_OFFSET)) return 0;
    if (bpf_probe_read_user(&daddr, sizeof(daddr), pkt + DADDR_OFFSET)) return 0;
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        if (bpf_probe_read_user(&sport, sizeof(sport), pkt + SPORT_OFFSET)) return 0;
        if (bpf_probe_read_user(&dport, sizeof(dport), pkt + DPORT_OFFSET)) return 0;
    }
    bpf_printk("proto=%u src=%x\n", proto, saddr);
    bpf_printk("dst=%x sport=%u\n", daddr, (__u16)(sport >> 8 | sport << 8));
    bpf_printk("dport=%u\n", (__u16)(dport >> 8 | dport << 8));
    // added LSB specifies entry (0) or exit (1)
    __u32 key = PT_REGS_IP(ctx) << 1;
    __u64 init = 1, *val = bpf_map_lookup_elem(&counters, &key);
    if (val) (*val)++;
    else bpf_map_update_elem(&counters, &key, &init, BPF_ANY);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}

SEC("uretprobe")
int do_uretprobe(struct pt_regs *ctx) {
    __u32 key = (PT_REGS_IP(ctx) << 1) | 1;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &key, sizeof(key));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
