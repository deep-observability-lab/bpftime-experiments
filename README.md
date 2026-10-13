# Tracing DPDK `testpmd` with bpftime (userspace eBPF)

This project uses **[bpftime](https://github.com/eunomia-bpf/bpftime)**, a userspace eBPF runtime, to instrument the DPDK test application **`dpdk-testpmd`** while it forwards packets. A libbpf-based loader attaches a **uprobe** and a **uretprobe** to a list of function offsets in the `dpdk-testpmd` binary. The eBPF programs then:

* **count calls** per probed address in a per-CPU hash map,
* **read packet headers** (Ethernet, IPv4, TCP/UDP ports) from the `struct rte_mbuf` passed as the first argument,
* **trace conditionally**: only calls whose packet matches a user-supplied 5-tuple filter are counted and reported,
* **stream entry/exit events** to userspace through a **perf event buffer** (`BPF_MAP_TYPE_PERF_EVENT_ARRAY`).

The loader writes the raw results to two binary files. A separate **post-processing tool** (`post`) turns them into per-function call counts, an ENTER/EXIT event trace, and a caller→callee **function graph**.

**Why userspace eBPF?** DPDK bypasses the kernel network stack and runs in busy-polling userspace threads. Kernel uprobes cost a trap into the kernel on every hit, which is expensive on a hot packet path. bpftime runs the same libbpf/clang-built eBPF programs inside the target process by rewriting its binary, so the probe overhead is lower and the toolchain stays the same.

---

## Table of contents

1. [Repository layout](#1-repository-layout)
2. [Prerequisites and installation](#2-prerequisites-and-installation)
3. [What was done](#3-what-was-done)
4. [How to run](#4-how-to-run)
5. [Post-processing and interpreting results](#5-post-processing-and-interpreting-results)
6. [Troubleshooting and known limitations](#6-troubleshooting-and-known-limitations)
7. [References](#7-references)

---

## 1. Repository layout

```
bpftime-experiments/
├── README.md        # Description of the project (Current file) 
├── Makefile         # Builds libbpf, bpftool, the eBPF object, the skeleton, `uprobe` and `post` (set BPFTROOT first)
├── uprobe.bpf.c     # eBPF programs: do_uprobe / do_uretprobe, mbuf/packet parsing, 5-tuple filter, maps
├── uprobe.c         # libbpf loader: parses the filter args and funcs.conf, finds the testpmd base, attaches probes, polls the perf buffer, writes output files
├── uprobe.h         # Shared constants: output file names (revents.txt, rcounts.txt), MAX_LINE, FUNC (=32)
├── post.c           # Post-processor: decodes rcounts.txt/revents.txt into call counts, ENTER/EXIT trace and function graph
├── funcs.conf       # Input: "<function_name> <offset> [<offset> ...]" lines (16 functions, 22 offsets) inside dpdk-testpmd
└── .gitignore       # Ignores .output/, uprobe, post, *.txt (run outputs) and *.conf
```

Generated at build/run time (not in the repository):

```
.output/               # Build directory: libbpf.a, bpftool, uprobe.bpf.o, uprobe.skel.h, uprobe.o
uprobe                 # Loader binary
post                   # Post-processing binary
revents.txt            # BINARY event stream (despite the .txt suffix), written by uprobe
rcounts.txt            # BINARY base address + per-address counts (despite the .txt suffix), written by uprobe
```
---

## 2. Prerequisites and installation

### 2.1 Tested environment

The experiments were run in this environment:

| Component | Version / details |
|---|---|
| OS | Ubuntu 24.04.3 LTS (Noble) |
| Kernel | 7.0.0-31-generic |
| Machine | QEMU VM (machine type "Standard PC Q35 + ICH9 2009"), 6 lcores, 1 NUMA node |
| Compilers / build tools | clang 18.1.3 (Ubuntu 1ubuntu1), llvm-config 18.1.3, gcc 13.3.0, cmake 3.28.3, meson 1.3.2, ninja 1.11.1 |
| DPDK | 24.11.5 (as reported by `pkg-config --modversion libdpdk`); testpmd installed at `/usr/local/bin/dpdk-testpmd` |
| bpftime | v0.9.0, commit `6bde654` (2026-08-14), built from source and installed to `~/.bpftime` |
| libbpf (bpftime `third_party`) | v1.6.0-25-g3f07747 |
| bpftool (bpftime `third_party`) | v7.6.0-22-g53c1852 |
| Virtual devices | Two DPDK TAP PMD ports (`net_tap0` → `tap0`, `net_tap1` → `tap1`), each moved into its own network namespace |
| Traffic generator | `iperf3` |

### 2.2 What the project itself assumes (from the source)

| Assumption | Where |
|---|---|
| `dpdk-testpmd` is installed at **`/usr/local/bin/dpdk-testpmd`**. The path is hard-coded as `BINARY`. | `uprobe.c` |
| `dpdk-testpmd` is **already running** when `uprobe` starts. The loader runs `pidof dpdk-testpmd` and reads `/proc/<pid>/maps` to find the binary's load base. | `uprobe.c` |
| `funcs.conf` is in the **current working directory**. | `uprobe.c` (`#define CONF "funcs.conf"`) |
| `revents.txt` / `rcounts.txt` are written to and read from the **current working directory**. | `uprobe.h`, `uprobe.c`, `post.c` |
| The bpftime source tree provides `third_party/libbpf`, `third_party/bpftool` and `third_party/vmlinux/<arch>/vmlinux.h`. | `Makefile` (`BPFTROOT`) |
| Build tools: `clang` (BPF target), `gcc`, `make`, `libelf` and `zlib` (link flags `-lelf -lz`). | `Makefile` |
| The offsets in `funcs.conf` belong to the exact `dpdk-testpmd` binary in use. They must be regenerated after every rebuild (see [3.1.1](#311-generating-funcsconf-offsets)). | `funcs.conf` |
| `pmd_rx_burst` / `pmd_tx_burst` in `funcs.conf` are the RX/TX burst functions of DPDK's **TAP PMD** (`drivers/net/tap/rte_eth_tap.c`), which is the virtual device used in the experiments. | `funcs.conf` |
| `pkt_burst_io_forward` is testpmd's **io** forwarding engine (the default forward mode). | `funcs.conf` |

### 2.3 OS packages (Ubuntu 24.04)

```bash
sudo apt-get update

# bpftime build dependencies (from bpftime's build-and-test docs);
# on Ubuntu 24.04, clang/llvm resolve to 18.1.3, gcc to 13.3.0, cmake to 3.28.3
sudo apt-get install \
    libelf1 libelf-dev libssl-dev zlib1g-dev make cmake git libboost-all-dev \
    binutils-dev libyaml-cpp-dev ca-certificates clang llvm pkg-config llvm-dev

# DPDK build dependencies; meson resolves to 1.3.2, ninja to 1.11.1
sudo apt-get install build-essential meson ninja-build python3-pyelftools libnuma-dev

# experiment tools: iperf3 for traffic, iproute2 for network namespaces,
# binutils for readelf (funcs.conf offsets)
sudo apt-get install iperf3 iproute2 binutils
```

### 2.4 Build and install bpftime (v0.9.0 → `~/.bpftime`)

The source checkout is also used as `BPFTROOT` when building this project. The example below places it at `~/Desktop/bpftime`:

```bash
mkdir -p ~/Desktop && cd ~/Desktop
git clone https://github.com/eunomia-bpf/bpftime.git
cd bpftime
git checkout v0.9.0                 # or: git checkout 6bde654
git submodule update --init --recursive
make release JOBS=$(nproc)          # builds and installs into ~/.bpftime
export PATH=$PATH:~/.bpftime
~/.bpftime/bpftime --help           # sanity check
```

The equivalent CMake path is:

```bash
cmake -Bbuild -DCMAKE_BUILD_TYPE:STRING=Release -DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_INFO
cmake --build build --config Release --target install
```

The bundled tool versions should match the tested environment:

```bash
git -C third_party/libbpf describe --tags    # expected: v1.6.0-25-g3f07747
git -C third_party/bpftool describe --tags   # expected: v7.6.0-22-g53c1852
```

> bpftime is installed for your user only (`~/.bpftime`). The run commands use `sudo -E ~/.bpftime/bpftime ...`. `-E` keeps your environment (including `HOME`), so bpftime uses the agent and syscall-server libraries in your `~/.bpftime` instead of looking under `/root/.bpftime`.

### 2.5 Build and install DPDK 24.11.5 / testpmd

The loader expects `/usr/local/bin/dpdk-testpmd`, which is where a default `meson install` (prefix `/usr/local`) puts it:

```bash
wget https://fast.dpdk.org/rel/dpdk-24.11.5.tar.xz
tar xJf dpdk-24.11.5.tar.xz
cd dpdk-stable-24.11.5
meson setup build -Dbuildtype=debug   # -O0 debug build (required, see note below)
cd build
ninja
sudo meson install
sudo ldconfig

pkg-config --modversion libdpdk    # expected: 24.11.5
ls -l /usr/local/bin/dpdk-testpmd
```

> **testpmd must be built in debug mode.** DPDK 24.11.5 defaults to a `release` build (`-O3`). In that build, most functions in `funcs.conf` are inlined and have no symbol, so they cannot be probed: only 6 of the 16 functions exist. The `funcs.conf` offsets assume the debug build.

Keep the symbol table (do not strip the binary). `funcs.conf` offsets are read from it with `readelf` (see [3.1.1](#311-generating-funcsconf-offsets)).

### 2.6 Hugepages

```bash
sudo sysctl -w vm.nr_hugepages=1024
grep Huge /proc/meminfo
```

testpmd is started with `--in-memory`, so no hugetlbfs mount point has to be set up.

### 2.7 Virtual devices and network namespaces

No physical NIC is needed. testpmd creates two TAP PMD ports (`--vdev='net_tap0,iface=tap0' --vdev='net_tap1,iface=tap1'`). Each port shows up as a kernel TAP interface. The helper script `vetap.sh` (section [4.2](#42-step-by-step)) moves each TAP interface into its own network namespace:

```
 ns1                          dpdk-testpmd (io forwarding)                       ns2
 tap0 10.1.1.1  <-->  port 0 (net_tap0)  <==>  port 1 (net_tap1)  <-->  tap1 10.1.1.3
```

Because the two IP addresses live in different namespaces, the kernel cannot route between them directly. Traffic from ns1 to ns2 has to go through testpmd, which forwards everything received on port 0 out of port 1 and vice versa.

> If you use another PMD (for example `net_null` or a real NIC), the PMD's RX/TX functions are different. Replace the `pmd_rx_burst` / `pmd_tx_burst` lines in `funcs.conf` with the right ones.

### 2.8 Build this project

1. Point `BPFTROOT` at your bpftime source directory (the checkout from 2.4). A **trailing slash** is recommended; without it the bundled uapi include path is silently ignored and system headers are used (see [Troubleshooting](#6-troubleshooting-and-known-limitations)). Either edit the `Makefile`:

   ```make
   # change the following path to the root directory of bpftime
   BPFTROOT := path/to/bpftime
   ```

   or set it in the environment / on the command line:

   ```bash
   export BPFTROOT=$HOME/Desktop/bpftime/
   ```

2. Build with one of these commands:

   ```bash
   make BPFTROOT=$BPFTROOT        # builds ./uprobe and ./post
   ```

   ```bash
   make V=1 BPFTROOT=$BPFTROOT    # same, with verbose output
   ```

   To start over, run `make clean`. It deletes `.output/`, `uprobe` and `post`, so run it **before** a build, not after:

   ```bash
   make clean
   ```

   Pass it on the command line as shown. The `Makefile` assigns `BPFTROOT := path/to/bpftime` itself, which overrides a value that is only exported in the environment.

   The build pipeline in the `Makefile` runs these steps:
   * `libbpf.a` is built statically from `$(BPFTROOT)/third_party/libbpf/src`.
   * A bootstrap `bpftool` is built from `$(BPFTROOT)/third_party/bpftool/src`.
   * `uprobe.bpf.c` is compiled with `clang -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)`, then passed through `bpftool gen object` to produce `.output/uprobe.bpf.o`.
   * `bpftool gen skeleton` generates `.output/uprobe.skel.h`.
   * `uprobe.c` is compiled and linked with `libbpf.a -lelf -lz` into `./uprobe`.
   * `post.c` is built with a plain `gcc post.c -o post`.

---

## 3. What was done

All experiments share **one** eBPF object (`uprobe.bpf.c`) and **one** loader (`uprobe.c`). The features below are layers of that single pipeline, not separate programs.

### 3.0 Which features from the project description actually exist

| Feature | Present? | Where |
|---|---|---|
| Counting function calls | **Yes** | `counters` map in `uprobe.bpf.c`, dumped by `uprobe.c`, printed by `post.c` |
| Packet (header) tracing | **Yes** Headers are parsed and used for filtering| `uprobe.bpf.c` |
| Conditional tracing | **Yes**, a 5-tuple filter with `0` as a wildcard | `target` map + CLI args of `uprobe` |
| uprobe / uretprobe attachment | **Yes** | `do_uprobe` / `do_uretprobe`, `bpf_program__attach_uprobe()` |
| Ring buffer | **No.** There is no `BPF_MAP_TYPE_RINGBUF` / `ring_buffer__*` anywhere in the code. | — |
| Perf buffer | **Yes** | `events` map (`BPF_MAP_TYPE_PERF_EVENT_ARRAY`), `perf_buffer__new/poll` |
| Post-processing | **Yes**: counts, event trace, function graph | `post.c` |
| Scripts | Only the helper `vetap.sh` (namespace setup, listed in section 4.2, not part of the repository) | — |

### 3.1 Function selection: `funcs.conf`

Each line has a function name followed by one or more **offsets inside `/usr/local/bin/dpdk-testpmd`**. A function name can have several offsets. Many of the listed functions are `static inline` DPDK helpers, so they appear in the binary as several separate copies.

```
rte_pktmbuf_read 0x7a6d7d
rte_net_get_ptype 0x7a71d0
rte_lcore_id 0x802749 0x256b80 0x7a9e01 0x2c65e47
...
pmd_rx_burst 0x2c6cc62
pmd_tx_burst 0x2c6d6b1
pkt_burst_io_forward 0x23b96f
rte_eth_rx_burst 0x23ae4e 0x256bcb
common_fwd_stream_transmit 0x23b7ea
```

The current file lists 16 functions and 22 offsets. Both programs read it:

* `uprobe` reads **only the offsets** and attaches a uprobe plus a uretprobe to each one (up to 512 offsets, `LINKS/2`).

* `post` reads **name ↔ offset pairs** to turn addresses back into names (up to 32 pairs, `FUNC`).

> The offsets are specific to one build of `dpdk-testpmd`. Regenerate them for your own binary as described below.

#### 3.1.1 Generating `funcs.conf` offsets

Offsets are taken from the ELF symbol table of the installed binary with `readelf`. For each function:

```bash
readelf -Ws /usr/local/bin/dpdk-testpmd | grep <func>
```

The **Value** column (the symbol address) is the offset that goes into `funcs.conf`. Example for `rte_pktmbuf_read`:

```
12797: 00000000007c01ef  5008 FUNC    GLOBAL DEFAULT   16 __rte_pktmbuf_read
 5963: 000000000026efb9   109 FUNC    LOCAL  DEFAULT   16 rte_pktmbuf_read
14175: 00000000006ce282   109 FUNC    LOCAL  DEFAULT   16 rte_pktmbuf_read
...
```

How to read this:

* `rte_pktmbuf_read` is a `static inline` function in a DPDK header. Every compilation unit that uses it and does not inline it gets its **own LOCAL copy**, so the same name appears several times with different addresses. That is why one function can have several offsets on its `funcs.conf` line, for example `rte_lcore_id 0x802749 0x256b80 0x7a9e01 0x2c65e47`. Pick the copies on the code path you want to trace, or list all of them.
* `grep` matches substrings. Check the last column for an exact name match: `__rte_pktmbuf_read` (GLOBAL) is a different function.
* Write the values as hex with a `0x` prefix, dropping the leading zeros: `000000000026efb9` → `0x26efb9`.
* Leave out lines whose Value is `0` or whose type is not `FUNC`.

A one-liner that prints all LOCAL/GLOBAL copies of an exact name in `funcs.conf` format:

```bash
f=rte_pktmbuf_read
readelf -Ws /usr/local/bin/dpdk-testpmd \
  | awk -v f="$f" '$4=="FUNC" && $8==f && $2!~/^0+$/ && !seen[$2]++ {v=$2; sub(/^0+/,"",v); printf " 0x%s", v} END {print ""}' \
  | sed "s/^/$f/"
```

> **Regenerate the offsets whenever testpmd is rebuilt or reinstalled.** Any change in DPDK version, build options or compiler moves the functions, and old offsets then point into the middle of unrelated code. The example output above comes from a different build than the committed `funcs.conf` (which lists `rte_pktmbuf_read 0x7a6d7d`), and that is exactly the reason.
>
> `bpf_program__attach_uprobe()` expects a file offset, while `readelf -s` prints a virtual address. The two are the same when the executable segment's `VirtAddr` equals its `Offset` in `readelf -lW /usr/local/bin/dpdk-testpmd`, which is the usual layout for GNU ld PIE binaries. If they differ, subtract `VirtAddr - Offset` of that segment.


### 3.2 Experiment: function call counting

**Files:** `uprobe.bpf.c` (map `counters`, program `do_uprobe`), `uprobe.c` (dump), `post.c` (report).

**Hook:** a uprobe on every offset in `funcs.conf`.

**How it works.** The map key is built from the instruction pointer at the probe, which is the probed address. It is shifted left by one bit so that the lowest bit can mark entry (0) or exit (1). The value is a per-CPU 64-bit counter:

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, FUNC);          // 32
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");
...
// added LSB specifies entry (0) or exit (1)
key = (__u32)(PT_REGS_IP(ctx) << 1);
__u64 init = 1, *val = bpf_map_lookup_elem(&counters, &key);
if (val) (*val)++;
else bpf_map_update_elem(&counters, &key, &init, BPF_ANY);
```

When the loader exits (Ctrl-C / SIGTERM), `uprobe.c` iterates the map with `bpf_map__get_next_key`, sums the per-CPU values, and writes them to `rcounts.txt`. Before the counts, it writes the testpmd load base so that `post` can turn runtime addresses back into file offsets.

> Only **entries** are counted, and only for calls that **pass the packet filter** (section 3.4). A call is counted only if its first argument points to a readable IPv4 `rte_mbuf` that matches the filter. With all-wildcard arguments (`0 0 0 0 0`), this still means "IPv4 packets only".

### 3.3 Experiment: packet header tracing (argument tracing)

**File:** `uprobe.bpf.c`.

**Hook:** same probes. The **first function argument** is treated as a `struct rte_mbuf *`.

**How it works.** The program follows the mbuf to the packet data with `bpf_probe_read_user`. All offsets are hard-coded:

| Constant | Value | Meaning |
|---|---|---|
| (offset 0) | 0 | `rte_mbuf.buf_addr` (pointer to the buffer) |
| `DATA_OFF_OFFSET` | 16 | `rte_mbuf.data_off` (`u16`) |
| `EHTERTYPE_OFFSET` | 12 | Ethernet EtherType |
| `PROTO_OFFSET` | 23 | IPv4 protocol (14 + 9) |
| `SADDR_OFFSET` / `DADDR_OFFSET` | 26 / 30 | IPv4 source / destination |
| `SPORT_OFFSET` / `DPORT_OFFSET` | 34 / 36 | L4 ports (assumes a 20-byte IPv4 header) |
| `NORD_ETH_P_IP` | `0x0008` | `ETH_P_IP` (0x0800) as read from network order on a little-endian CPU |

```c
__u8 *mbuf = (__u8 *)PT_REGS_PARM1(ctx), *buf_addr, *pkt, proto;
if (!mbuf) return 0;
if (bpf_probe_read_user(&buf_addr, sizeof(buf_addr), mbuf) != 0) return 0;
__u16 data_off;
if (bpf_probe_read_user(&data_off, sizeof(data_off), mbuf + DATA_OFF_OFFSET) != 0) return 0;
pkt = buf_addr + data_off;
if (bpf_probe_read_user(&ethertype, sizeof(ethertype), pkt + EHTERTYPE_OFFSET) != 0) return 0;
if (ethertype != NORD_ETH_P_IP) return 0;
```

Ports are read only when `proto` is TCP or UDP.

### 3.4 Experiment: conditional tracing (5-tuple filter)

**Files:** `uprobe.bpf.c` (map `target`), `uprobe.c` (command-line arguments).

**How it works.** The loader takes exactly five arguments and stores them in a one-entry array map named `target`:

```
usage: ./uprobe proto src_addr dst_addr src_port dst_port (use 0 as wildcard)
```

* `proto`: IP protocol number as a decimal integer (for example `6` = TCP, `17` = UDP, `1` = ICMP)
* `src_addr` / `dst_addr`: IPv4 dotted-quad, parsed with `inet_pton`, or `0`
* `src_port` / `dst_port`: decimal and converted with `htons`, or `0`

```c
struct flow { __u8 proto; __be32 saddr; __be32 daddr; __be16 sport; __be16 dport; };
...
struct flow *tf = bpf_map_lookup_elem(&target, &key);
if (tf->proto != 0 && proto != tf->proto) return 0;
if (tf->saddr != 0 && saddr != tf->saddr) return 0;
if (tf->daddr != 0 && daddr != tf->daddr) return 0;
if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
    if (tf->sport != 0 && sport != tf->sport) return 0;
    if (tf->dport != 0 && dport != tf->dport) return 0;
}
```

The loader writes the filter into the map with `bpf_map__update_elem(skel->maps.target, ...)` after `uprobe_bpf__load()` and before it attaches the probes. A field set to `0` matches anything. A call is counted and emitted only if every non-zero field matches.

### 3.5 Experiment: uprobe / uretprobe attachment

**File:** `uprobe.c`.

**How it works.** For each offset `i` from `funcs.conf`, the loader creates two links on `/usr/local/bin/dpdk-testpmd`, for any PID (`-1`):

```c
// counter + entry
links[2*i]   = bpf_program__attach_uprobe(skel->progs.do_uprobe,    false, -1, BINARY, offs[i]);
// exit
links[2*i+1] = bpf_program__attach_uprobe(skel->progs.do_uretprobe, true,  -1, BINARY, offs[i]);
```

* `do_uprobe` (`SEC("uprobe")`) applies the filter, increments the counter and emits an **entry** event with key `IP<<1`.
* `do_uretprobe` (`SEC("uretprobe")`) applies the **same filter**, re-reading `PT_REGS_PARM1` at return time. It emits an **exit** event with key `(IP<<1)|1`. It does not count.

The loader is a normal libbpf program. When it runs under `bpftime load`, bpftime's syscall server intercepts the BPF and perf-event syscalls, and the probes are installed in testpmd's userspace by the bpftime agent instead of the kernel.

### 3.6 Experiment: event transport (perf buffer; no ring buffer)

**Files:** `uprobe.bpf.c` (map `events`), `uprobe.c` (consumer).

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 32); // placeholder, will be updated by userspace
    __type(key, __u32);
    __type(value, __u32);
} events SEC(".maps");
...
bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &key, sizeof(key));
```

* Before loading, the loader resizes `events` to the number of possible CPUs (`bpf_map__set_max_entries(..., libbpf_num_possible_cpus())`).
* It creates `perf_buffer__new(..., PAGEC = 2048 pages, handle_event, ...)` and polls it every 100 ms until SIGINT/SIGTERM.
* Each event payload is just the 4-byte key. `handle_event` appends **8 bytes per event** to `revents.txt`: `u32 key`, then `u32 cpu`.

### 3.7 Experiment: post-processing (counts, trace, function graph)

**File:** `post.c`. Details are in [section 5](#5-post-processing-and-interpreting-results).

---

## 4. How to run

Run the bpftime and post-processing commands from the project directory, because `funcs.conf` and the output files use relative paths.

### 4.1 Order of operations

`uprobe` looks up testpmd's PID and load base **when it starts**, so testpmd must be running first. Then the eBPF program is loaded with bpftime, and the bpftime agent is injected into the running testpmd:

```
[terminal 1]  dpdk-testpmd (interactive)       (must be /usr/local/bin/dpdk-testpmd)
[terminal 2]  vetap.sh                         (TAP interfaces -> namespaces ns1 / ns2)
[terminal 2]  bpftime load ./uprobe <filter>   (loader + syscall server; finds testpmd via pidof)
[terminal 3]  bpftime attach <testpmd pid>     (injects the agent; probes become active)
[terminal 4]  iperf3 server in ns2
[terminal 1]  testpmd> start
[terminal 3]  iperf3 client in ns1             (traffic flows through testpmd)
[terminal 2]  Ctrl-C                           (flushes revents.txt / rcounts.txt)
              ./post funcs.conf
```

> Upstream bpftime usually runs `bpftime load` and then `bpftime start <program>`. That order does not work here, because `uprobe` exits with `pid not found` if testpmd is not already running. That is why testpmd is started first and bpftime is injected with `bpftime attach`.

### 4.2 Step by step

**1. Reserve hugepages:**

```bash
sudo sysctl -w vm.nr_hugepages=1024
```

**2. Terminal 1: start testpmd** with two TAP ports:

```bash
sudo dpdk-testpmd --lcores=0-3 -n4 --in-memory \
    --vdev='net_tap0,iface=tap0' --vdev='net_tap1,iface=tap1' \
    -- -i --record-core-cycles
testpmd>                      # do not start forwarding yet
```

* `--lcores=0-3`: run on lcores 0–3 (lcore 0 is the main/interactive core).
* `-n4`: 4 memory channels.
* `--in-memory`: keep all hugepage memory in-process, without hugetlbfs files.
* `--vdev='net_tap0,iface=tap0'`, `--vdev='net_tap1,iface=tap1'`: create TAP PMD ports 0 and 1, with kernel interfaces `tap0` and `tap1`.
* `-i`: interactive prompt.
* `--record-core-cycles`: testpmd records CPU cycles spent per forwarding core, shown in its forwarding statistics.

> Optional: add `--no-pci` to the EAL options (before `--`) so that testpmd does not probe the machine's PCI NICs. Only the two TAP ports are needed.

**3. Create the namespaces** with `vetap.sh`. This script is not in the repository; create it next to the sources with this exact content:

```bash
#!/bin/sh
ip netns del ns1 2>/dev/null
ip netns add ns1
ip link set tap0 netns ns1
ip netns exec ns1 ip addr add 10.1.1.1/24 dev tap0
ip netns exec ns1 ip link set tap0 up

ip netns del ns2 2>/dev/null
ip netns add ns2
ip link set tap1 netns ns2
ip netns exec ns2 ip addr add 10.1.1.3/24 dev tap1
ip netns exec ns2 ip link set tap1 up
```

```bash
sudo ./vetap.sh               # after: chmod +x vetap.sh   (or: sudo sh vetap.sh)
```

The script creates two network namespaces, each holding one TAP interface. It (re)creates `ns1`, moves `tap0` into it and gives it `10.1.1.1/24`. It does the same for `ns2` with `tap1` and `10.1.1.3/24`. Both interfaces are brought up. Because the addresses are in separate namespaces, iperf3 traffic from ns1 (10.1.1.1) to ns2 (10.1.1.3) cannot take a kernel shortcut. It leaves through `tap0`, is received by testpmd on port 0, is forwarded by the **io** engine (`pkt_burst_io_forward`) to port 1, and arrives on `tap1` in ns2. Replies take the reverse path. Run the script **after** testpmd has started, because the TAP interfaces only exist while testpmd runs. Run it again after every testpmd restart.

**4. Terminal 2: load the eBPF program through bpftime** (in the project directory). `uprobe` takes exactly the five filter arguments `proto src_addr dst_addr src_port dst_port` (`0` = wildcard). It reads `funcs.conf` from the current directory by itself, so **do not pass `funcs.conf` as an argument**: a sixth argument makes `uprobe` print its usage message and exit.

```bash
git clone <project-repo-url> bpftime-experiments   # if you do not have the project source yet
cd bpftime-experiments        # must contain funcs.conf
# trace all IPv4 packets (all wildcards)
sudo -E ~/.bpftime/bpftime load ./uprobe 0 0 0 0 0
# or: only TCP packets from ns1 (10.1.1.1) to ns2 (10.1.1.3), any ports
sudo -E ~/.bpftime/bpftime load ./uprobe 6 10.1.1.1 10.1.1.3 0 0
# or: only the iperf3 data direction (TCP to the default iperf3 port 5201)
sudo -E ~/.bpftime/bpftime load ./uprobe 6 10.1.1.1 10.1.1.3 0 5201
```

> The filter is one-directional. With `src_addr = 10.1.1.1` / `dst_addr = 10.1.1.3`, the replies from 10.1.1.3 (such as TCP ACKs) do not match. Use `0 0 0 0 0` or swap the addresses to see the other direction.

**5. Terminal 3: attach to testpmd:**

```bash
sudo -E ~/.bpftime/bpftime attach $(pidof dpdk-testpmd)
```

**6. Terminal 4: start the iperf3 server in ns2:**

```bash
sudo ip netns exec ns2 iperf3 -s -B 10.1.1.3
```

**7. Terminal 1: start forwarding:**

```bash
testpmd> start                # default forward mode is "io" (pkt_burst_io_forward)
```

**8. Run the iperf3 client in ns1** (5-second TCP test through testpmd):

```bash
sudo ip netns exec ns1 iperf3 -c 10.1.1.3 -t 5
```

**9. Stop and collect:**

* Stop the loader with **Ctrl-C** in the `bpftime load` terminal (terminal 2). Counts are written **only on exit**, after the polling loop ends. Events are streamed to `revents.txt` while the loader runs.
* Stop iperf3 server (Ctrl-C in terminal 4) and testpmd:

```bash
ls -l revents.txt rcounts.txt
testpmd> stop                 # also prints forwarding statistics
testpmd> quit
```

**10. Post-process** (see section 5):

```bash
./post funcs.conf > post.txt
```

The output is large, because every ENTER/EXIT event is printed: about 776k lines for a 5 s iperf3 run. Open `post.txt` with `less`, or look at the counts and the graph with `head` and `sed -n '/function graph/,$p' post.txt`.

### 4.3 Sample output

The outputs below come from a test run of the procedure above. `funcs.conf` was regenerated with `readelf` for that run's testpmd build (section 3.1.1) and listed `rte_net_get_ptype`, `rte_mbuf_raw_alloc`, `rte_pktmbuf_free`, `pmd_rx_burst`, `pmd_tx_burst` and `pkt_burst_io_forward`.

**Run 1: all IPv4 packets** (`./uprobe 0 0 0 0 0`)

iperf3 client summary:

```
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-5.00   sec   175 MBytes   294 Mbits/sec   39            sender
[  5]   0.00-5.04   sec   173 MBytes   288 Mbits/sec                  receiver
```

testpmd statistics after `stop`:

```
  +++++++++++++++ Accumulated forward statistics for all ports+++++++++++++++
  RX-packets: 190051         RX-dropped: 0             RX-total: 190051
  TX-packets: 190051         TX-dropped: 0             TX-total: 190051
  ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  CPU cycles/packet=64364.19 (busy cycles=12232477826 / total io packets=190051) at 2400 MHz Clock
```

`./post funcs.conf` (event trace shortened):

```
----<function call counts>----
rte_pktmbuf_free: 190048
rte_net_get_ptype: 190048

----<entry and exit events>----
ENTER rte_net_get_ptype on cpu=1
EXIT  rte_net_get_ptype on cpu=1
ENTER rte_pktmbuf_free on cpu=1
EXIT  rte_pktmbuf_free on cpu=1
EXIT  pmd_tx_burst on cpu=1
EXIT  pkt_burst_io_forward on cpu=1
ENTER rte_net_get_ptype on cpu=1
EXIT  rte_net_get_ptype on cpu=1
...

----<function graph>----
* --[190048]--> rte_net_get_ptype
* --[190048]--> rte_pktmbuf_free
* --[7943]--> pmd_tx_burst
```

**Run 2: iperf3 data direction only** (`./uprobe 6 10.1.1.1 10.1.1.3 0 5201`, 3 s iperf3 run; testpmd forwarded 129124 packets in total)

```
----<function call counts>----
rte_pktmbuf_free: 85675
rte_net_get_ptype: 85675

----<function graph>----
* --[85675]--> rte_net_get_ptype
* --[85675]--> rte_pktmbuf_free
* --[2689]--> pmd_tx_burst
```

The filter keeps only the ns1 → ns2 TCP data packets, so the counts are lower than the total number of forwarded packets. In both runs, `pmd_rx_burst`, `pmd_tx_burst`, `pkt_burst_io_forward` and `rte_mbuf_raw_alloc` have no ENTER events, because their first argument is not an `rte_mbuf *` (limitation 1). The unmatched EXIT events come from the uretprobe re-reading `PT_REGS_PARM1` (limitation 2).

---

## 5. Post-processing and interpreting results

### 5.1 File formats (binary, little-endian, native)

| File | Layout |
|---|---|
| `rcounts.txt` | `u64 base` (testpmd load base, the first mapping of `/usr/local/bin/dpdk-testpmd` in `/proc/<pid>/maps`), followed by repeated `{ u32 key; u64 count; }` (12 bytes each, unpadded) |
| `revents.txt` | Repeated `{ u32 key; u32 cpu; }`, in the order the perf buffer delivered them |

`key` is `(runtime_IP << 1) | is_exit`, truncated to 32 bits.

### 5.2 What `post` does

```bash
./post <function mappings file>      # normally: ./post funcs.conf
```

1. **Mapping:** reads `name offset...` lines into up to 32 `(offset, name)` pairs.
2. **Address decoding:** for every key it computes `offset = (key - (u32)(base << 1)) >> 1`, which removes the ASLR base and the entry/exit bit. It then looks up the name. The exit flag is `key & 1`.
3. **Call counts:** prints `name: count` for every counter whose offset is listed in the mapping file.
4. **Event trace:** prints `ENTER name on cpu=N` / `EXIT  name on cpu=N` in file order.
5. **Function graph:** replays the events against a shadow call stack (max depth 4096):
   * on **ENTER**, it records an edge `(caller = top of stack or 0, callee)` and increments the edge's count, then pushes the callee;
   * on **EXIT**, it pops the stack.
   
   It prints each edge as `caller --[count]--> callee`, using `*` as the caller for root calls.

```c
if (is_exit && st.depth > 0)   // remove from stack
    st.depth--;
else {                         // is entry, create edge or increment count
    e = (struct edge){ .caller = 0, .callee = key, .count = 1 };
    if (st.depth > 0) e.caller = st.addrs[st.depth - 1];
    ...
}
```

### 5.3 Interpreting the results

* **Counts** are the number of **filtered** entries per probed address, summed over all CPUs. If a function has several offsets (inlined copies), `post` prints one line per offset, all with the same name. Add them up for a per-function total.
* **Events** are only events that passed the filter. The `cpu` value is the CPU that emitted the event, which tells you which lcore handled the packet.
* **The graph** is a dynamic call graph limited to the probed functions. An edge `A --[n]--> B` means B was entered n times while A was the innermost traced function still open. The stack is global, not per-CPU or per-thread. With several forwarding lcores, interleaved events from different CPUs can create artificial edges, so use a single forwarding core when you want a clean graph.
* Functions whose first argument is **not** an `rte_mbuf *` will rarely or never appear (see Limitations). Examples are `rte_lcore_id(void)`, `rte_eth_rx_burst(port_id, ...)`, `pmd_rx_burst(queue, ...)`, `pkt_burst_io_forward(fs)` and `rte_mbuf_raw_alloc(mempool)`.

---

## 6. Troubleshooting and known limitations

### 6.1 Troubleshooting

| Symptom (message printed by the tools) | Likely cause / fix |
|---|---|
| `usage: ./uprobe proto src_addr dst_addr src_port dst_port (use 0 as wildcard)` | `uprobe` needs exactly 5 arguments. Use `0 0 0 0 0` for "everything IPv4". |
| `failed to fopen input file` | `funcs.conf` is not in the current directory. Run from the project directory. |
| `invalid offset '...' in funcs.conf` / `no offsets found in funcs.conf` | Malformed `funcs.conf`. It must be space-separated, with numbers in hex (`0x..`) or decimal. |
| `pid not found` | testpmd is not running, or its process name is not `dpdk-testpmd`. Start testpmd **before** `uprobe`. |
| `bin base not found` | testpmd was not started from `/usr/local/bin/dpdk-testpmd`, for example `./build/app/dpdk-testpmd`. Install it with `meson install` or change `BINARY` in `uprobe.c`. |
| `usage: ...` right after `bpftime load ./uprobe funcs.conf ...` | `funcs.conf` was passed as an argument. `uprobe` reads it from the current directory; pass only the 5 filter arguments. |
| `Cannot find device "tap0"` from `vetap.sh` | testpmd is not running (the TAP interfaces exist only while it runs), or `vetap.sh` already moved them into the namespaces. |
| iperf3 client cannot connect | Forwarding not started (`testpmd> start`), or the namespaces were not recreated after a testpmd restart. Check with `sudo ip netns exec ns1 ping -c 3 10.1.1.3`. |
| bpftime looks for libraries under `/root/.bpftime` | Run it with `sudo -E` so your `HOME` (and `~/.bpftime`) is kept. |
| `<offset>: failed to attach uprobe` / `uretprobe` | The offset is not valid for your binary. Regenerate `funcs.conf` (section 3.1.1). |
| `failed to load and verify BPF skeleton` | Check the libbpf messages printed to stderr. Make sure the program was built against bpftime's libbpf/vmlinux. |
| `perf_buffer__new failed` / `perf_buffer__poll failed: <err>` | The perf event array is not available, or bpftime is not intercepting the calls. Make sure you started it with `bpftime load`. |
| Build cannot find `bpf/bpf_helpers.h` or the uapi headers | A **trailing slash** on `BPFTROOT` is recommended. The Makefile line `-I$(BPFTROOT)third_party/libbpf/include/uapi` has no `/` between the variable and `third_party`; without the slash, the bundled uapi include path is silently ignored and system headers are used. |
| Build cannot find `vmlinux.h` / bpftool sources | Run `git submodule update --init --recursive` in the bpftime checkout. |
| `rcounts.txt` empty or missing | The loader was killed with SIGKILL, or exited on an error. Counts are written only after a clean SIGINT/SIGTERM. |
| `post`: `call stack exceeded MAX_DEPTH (4096), aborting` | Many ENTER events without matching EXIT events. See the uretprobe limitations below. |
| `post` prints nothing for some functions | Their first argument is not an mbuf (filtered out), or the mapping/offset does not match the decoded address. |

### 6.2 Known limitations

1. **Every probed function is assumed to take `struct rte_mbuf *` as its first argument.** Many functions in `funcs.conf` do not, for example `rte_lcore_id`, `rte_constant_bswap16`, `rte_ipv4_hdr_len`, `rte_mbuf_raw_alloc`, `rte_eth_rx_burst`, `pmd_rx_burst`/`pmd_tx_burst`, `pkt_burst_io_forward` and `common_fwd_stream_transmit`. For those, the mbuf/packet reads fail or read garbage, the call is dropped, and it is **neither counted nor traced**.
2. **The uretprobe re-reads `PT_REGS_PARM1` at function return.** The first-argument register is not preserved across a call, so exit events can be filtered out wrongly. That leaves the ENTER/EXIT trace and the function graph unbalanced.
3. **Exit address decoding.** `post` assumes that the IP seen in the uretprobe decodes to the same function offset as the entry. With kernel uretprobes, the IP at return is the caller's return address. Under bpftime v0.9.0, the exit-probe address decodes to the same function as the entry; this was verified in a test run.
4. **Inlined call sites are invisible.** The `funcs.conf` offsets are real `FUNC` symbols (out-of-line LOCAL copies of `static inline` helpers, section 3.1.1), so they have a normal call and return. Calls that the compiler inlined into their caller have no symbol and are never probed, so counts cover only the out-of-line copies you listed.
5. **Fixed packet layout:** untagged Ethernet + IPv4 with a 20-byte header (no IP options, no VLAN, no IPv6). Ports are read at fixed offsets 34/36. Only the first segment (`buf_addr + data_off`) is parsed.
6. **Little-endian only:** `NORD_ETH_P_IP` is hard-coded as `0x0008`.
7. **Hard-coded paths:** `/usr/local/bin/dpdk-testpmd`, `funcs.conf`, `revents.txt`, `rcounts.txt`. `pidof` takes the **first** PID when several testpmd instances are running.
8. **Size limits:** `counters` has 32 entries (`FUNC`). `post` keeps at most 32 name/offset pairs and at most `32*31` graph edges. The loader accepts at most 512 offsets (1024 links).
9. **32-bit keys:** `IP << 1` is truncated to 32 bits. Decoding works only if the offset inside the binary is below 2 GiB, which holds for testpmd.
10. **Counts only on clean exit.** The map is dumped after the poll loop ends.
11. **`post` loads its whole edge list on the stack and does a linear search.** That is fine for the small configs used here.
12. The **offsets in `funcs.conf` are build-specific.** They must be regenerated with `readelf` (section 3.1.1) whenever testpmd is rebuilt.

---

## 7. References

* bpftime: https://github.com/eunomia-bpf/bpftime
  * Build & test: https://eunomia.dev/bpftime/documents/build-and-test/
  * Usage (`load` / `start` / `attach`, LD_PRELOAD mode): https://eunomia.dev/bpftime/documents/usage
  * Y. Zheng et al., *Extending Applications Safely and Efficiently*, OSDI '25
* DPDK documentation: https://doc.dpdk.org/guides/
  * System requirements and hugepages: https://doc.dpdk.org/guides/linux_gsg/sys_reqs.html
  * Compiling DPDK: https://doc.dpdk.org/guides/linux_gsg/build_dpdk.html
  * testpmd user guide: https://doc.dpdk.org/guides/testpmd_app_ug/
  * TAP PMD: https://doc.dpdk.org/guides/nics/tap.html
  * `struct rte_mbuf` layout: `lib/mbuf/rte_mbuf_core.h` in the DPDK source tree
* libbpf: https://github.com/libbpf/libbpf (API: `bpf_program__attach_uprobe`, `perf_buffer__new`, `perf_buffer__poll`)
* bpftool skeletons: https://github.com/libbpf/bpftool
* Linux uprobe tracing: https://docs.kernel.org/trace/uprobetracer.html
