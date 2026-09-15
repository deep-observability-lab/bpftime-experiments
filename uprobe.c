// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include "uprobe.skel.h"
#include "uprobe.h"

#define warn(...)      fprintf(stderr, __VA_ARGS__)
#define round_up(x, y) ((((x) + ((y) - 1)) / (y)) * (y))

#define BINARY   "/usr/local/bin/dpdk-testpmd"
#define CONF     "funcs.conf"
#define LINKS    1024
#define PAGEC    2048
#define MAX_PATH 64
#define MAX_NAME 256

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) { return vfprintf(stderr, format, args); }

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

FILE *fp;

static void handle_event(void *ctx, int cpu, void *data, unsigned int size) {
    if (!fp) return;
    if (!data || size < sizeof(uint32_t)) return;
    fwrite(data, sizeof(uint32_t), 1, fp);
    fwrite(&cpu, sizeof(uint32_t), 1, fp);
}

struct flow {
    uint8_t  proto;
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
};

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr,
                "usage: %s proto src_addr dst_addr src_port dst_port (use 0 as wildcard)\n",
                argv[0]);
        return 1;
    }

    struct flow tf = {0};
    uint32_t key = 0;

    tf.proto = (uint8_t)atoi(argv[1]);

    if (strcmp(argv[2], "0") != 0)
        if (inet_pton(AF_INET, argv[2], &tf.saddr) != 1) {
            fprintf(stderr, "invalid source address: %s\n", argv[2]);
            return 1;
        }

    if (strcmp(argv[3], "0") != 0)
        if (inet_pton(AF_INET, argv[3], &tf.daddr) != 1) {
            fprintf(stderr, "invalid destination address: %s\n", argv[3]);
            return 1;
        }

    tf.sport = htons((uint16_t)atoi(argv[4]));
    tf.dport = htons((uint16_t)atoi(argv[5]));

    // read offsets from conf file
    fp = fopen(CONF, "r");
    if (!fp) {
        fprintf(stderr, "failed to fopen input file\n");
        return 1;
    }
    char line[MAX_LINE], *tok;
    size_t oi = 0, offs[LINKS / 2] = {0};
    while (fgets(line, MAX_LINE, fp) && oi < LINKS / 2) {
        line[strcspn(line, "\r\n")] = '\0';
        tok = strtok(line, " "); // skip name
        tok = strtok(NULL, " ");
        while (tok && oi < LINKS / 2) {
            char *endp;
            errno = 0;
            size_t off = strtoul(tok, &endp, 0);
            if (errno || endp == tok) {
                fprintf(stderr, "invalid offset '%s' in %s\n", tok, CONF);
                fclose(fp);
                return 1;
            }
            offs[oi++] = off;
            tok = strtok(NULL, " ");
        }
    }
    fclose(fp);
    if (oi == 0) {
        fprintf(stderr, "no offsets found in %s\n", CONF);
        return 1;
    }
    // find pid
    fp = popen("pidof dpdk-testpmd", "r");
    if (!fp) {
        fprintf(stderr, "popen failed\n");
        return 1;
    }
    int pid;
    if (fscanf(fp, "%d", &pid) != 1) {
        fprintf(stderr, "pid not found\n");
        pclose(fp);
        return 1;
    }
    pclose(fp);

    // get binary base
    char path[MAX_PATH], name[MAX_NAME];
    snprintf(path, MAX_PATH, "/proc/%d/maps", pid);
    fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "failed to fopen /proc/maps\n");
        return 1;
    }
    uint64_t base;
    int err = 1;
    while (fgets(line, MAX_LINE, fp)) {
        // format: address perms offset dev inode filename
        if (sscanf(line, "%" SCNx64 "-%*x %*s %*s %*s %*d %255s", &base, name) == 2
            && strcmp(name, BINARY) == 0) {
            err = 0;
            break;
        }
    }
    fclose(fp);
    if (err) {
        fprintf(stderr, "bin base not found\n");
        return 1;
    }

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Load and verify BPF application */
    struct uprobe_bpf *skel = uprobe_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open and load BPF skeleton\n");
        return 1;
    }

    struct bpf_link *links[LINKS] = {0};
    struct perf_buffer *pb = NULL;
    uint64_t tcount;
    int pret;
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0) {
        fprintf(stderr, "failed to get cpu count\n");
        return 1;
    }

    if (bpf_map__set_max_entries(skel->maps.events, ncpus) != 0) {
        fprintf(stderr, "failed to resize events map to %d cpus\n", ncpus);
        return 1;
    }

    u_int64_t counts[ncpus];
    /* Load & verify BPF programs */
    err = uprobe_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    if (bpf_map__update_elem(skel->maps.target,
                             &key, sizeof(key), &tf, sizeof(tf), BPF_ANY) != 0) {
        fprintf(stderr, "failed to pass target flow to eBPF\n");
        goto cleanup;
    }

    for (size_t i = 0; i < oi; i++) {
        // counter + entry
        links[2*i] = bpf_program__attach_uprobe(
            skel->progs.do_uprobe, false, -1, BINARY, offs[i]);
        if (!links[2*i]) {
            fprintf(stderr, "%zu: failed to attach uprobe\n", offs[i]);
            err = -1;
            goto cleanup;
        }
        // exit
        links[2*i+1] = bpf_program__attach_uprobe(
            skel->progs.do_uretprobe, true, -1, BINARY, offs[i]);
        if (!links[2*i+1]) {
            fprintf(stderr, "%zu: failed to attach uretprobe\n", offs[i]);
            err = -1;
            goto cleanup;
        }
    }

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), PAGEC, handle_event, NULL, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "perf_buffer__new failed\n");
        err = -1;
        goto cleanup;
    }

    fp = fopen(REVF, "wb");
    if (!fp) {
        fprintf(stderr, "failed to open revents.txt\n");
        err = -1;
        goto cleanup;
    }

    while (!exiting) {
        pret = perf_buffer__poll(pb, 100);
        if (pret < 0 && pret != -EINTR) {
            fprintf(stderr, "perf_buffer__poll failed: %d\n", pret);
            break;
        }
    }

    fclose(fp);

    fp = fopen(RCOUF, "wb");
    if (!fp) {
        fprintf(stderr, "failed to open rcounts.txt\n");
        err = -1;
        goto cleanup;
    }
    // also write binary base to rcounts.txt
    fwrite(&base, sizeof(uint64_t), 1, fp);
    while (bpf_map__get_next_key(skel->maps.counters, &key, &key, sizeof(key)) == 0
           && bpf_map__lookup_elem(skel->maps.counters, &key, sizeof(key),
                                 counts, round_up(sizeof(uint64_t), 8) * ncpus, 0) == 0) {
            tcount = 0;
            for (size_t i = 0; i < ncpus; i++) tcount += counts[i];
            fwrite(&key, sizeof(uint32_t), 1, fp);
            fwrite(&tcount, sizeof(uint64_t), 1, fp);
        }
    fclose(fp);

cleanup:
    for (size_t i = 0; i < LINKS && links[i]; i++)
        bpf_link__destroy(links[i]);
    if (pb) perf_buffer__free(pb);
    uprobe_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
