// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <stdlib.h>
#include "uprobe.skel.h"
#include <inttypes.h>
#include "uprobe.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define round_up(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#define BINARY "/usr/local/bin/dpdk-testpmd"
#define LINKS 1024
#define MAX_LINE 4096
#define MAX_NAME 64
#define PAGEC 2048

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) { return vfprintf(stderr, format, args); }

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

size_t offs[LINKS / 2] = {0};

static void handle_event(void *ctx, int cpu, void *data, unsigned int size) {
    const struct event *e = (const struct event *)data;
    printf("%s 0x%"PRIx32" on cpu=%d\n", e->is_exit ? "EXIT" : "ENTER", e->key, cpu);
}

int main(int argc, char **argv) {
    // read offsets from file
    if (argc != 2) {
        fprintf(stderr, "usage: %s offs.conf\n", argv[0]);
        return 1;
    }
    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        perror("fopen");
        return 1;
    }
    char line[MAX_LINE], *token;
    size_t oi = 0;
    if (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        token = strtok(line, " \t");
        while (token && oi < LINKS / 2) {
            offs[oi++] = strtoul(token, NULL, 0);
            token = strtok(NULL, " \t");
        }
    }
    fclose(fp);

    struct uprobe_bpf *skel;
    struct bpf_link *links[LINKS] = {0};
    int err, ncpus = libbpf_num_possible_cpus();
    uint64_t counts[ncpus], tcount;
    struct perf_buffer *pb;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Load and verify BPF application */
    skel = uprobe_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = uprobe_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    for (size_t i = 0; i < oi; i++) {
        // counter + entry
        links[2*i] = bpf_program__attach_uprobe(
            skel->progs.do_uprobe, false, -1, BINARY, offs[i]);
        if (!links[2*i]) {
            fprintf(stderr, "%zu: Failed to attach uprobe\n", offs[i]);
            err = -1;
            goto cleanup;
        }
        // exit
        links[2*i+1] = bpf_program__attach_uprobe(
            skel->progs.do_uretprobe, true, -1, BINARY, offs[i]);
        if (!links[2*i+1]) {
            fprintf(stderr, "%zu: Failed to attach uretprobe\n", offs[i]);
            err = -1;
            goto cleanup;
        }
    }

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), PAGEC, handle_event, NULL, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "perf_buffer__new failed\n");
        goto cleanup;
    }

    while (!exiting) perf_buffer__poll(pb, 100);

cleanup:
    puts("---------<function call counts>---------");
    __u32 key = {};
    while (bpf_map__get_next_key(skel->maps.counters, &key, &key, sizeof(key)) == 0)
        if (bpf_map__lookup_elem(skel->maps.counters, &key, sizeof(key),
                                 counts, round_up(sizeof(__u64), 8) * ncpus, 0) == 0) {
            tcount = 0;
            for (size_t i = 0; i < ncpus; i++) tcount += counts[i];
            printf("0x%"PRIx32": %lu\n", key, tcount);
        }
    for (size_t i = 0; i < LINKS && links[i]; i++) bpf_link__destroy(links[i]);
    if (pb) perf_buffer__free(pb);
    uprobe_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
