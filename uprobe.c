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

#define warn(...)      fprintf(stderr, __VA_ARGS__)
#define round_up(x, y) ((((x) + ((y) - 1)) / (y)) * (y))

#define LINKS 1024
#define PAGEC 2048

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) { return vfprintf(stderr, format, args); }

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

FILE *fp;

static void handle_event(void *ctx, int cpu, void *data, unsigned int size) {
    fwrite(data, sizeof(uint32_t), 1, fp);
    fwrite(&cpu, sizeof(uint32_t), 1, fp);
}

int main(int argc, char **argv) {
    // read offsets from file
    if (argc != 2) {
        fprintf(stderr, "usage: %s offs.conf\n", argv[0]);
        return 1;
    }
    fp = fopen(argv[1], "r");
    if (!fp) {
        fprintf(stderr, "failed to fopen offs.conf\n");
        return 1;
    }
    char line[MAX_LINE], *token;
    size_t oi = 0, offs[LINKS / 2] = {0};
    if (fgets(line, MAX_LINE, fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        token = strtok(line, " \t");
        while (token && oi < LINKS / 2) {
            offs[oi++] = strtoul(token, NULL, 0);
            token = strtok(NULL, " \t");
        }
    }
    fclose(fp);

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
    int err, ncpus = libbpf_num_possible_cpus();
    uint32_t key = {};
    uint64_t counts[ncpus], tcount;
    struct perf_buffer *pb;

    /* Load & verify BPF programs */
    err = uprobe_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load and verify BPF skeleton\n");
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

    while (!exiting) perf_buffer__poll(pb, 100);

    fclose(fp);

    fp = fopen(RCOUF, "wb");
    if (!fp) {
        fprintf(stderr, "failed to open rcounts.txt\n");
        err = -1;
        goto cleanup;
    }
    while (bpf_map__get_next_key(skel->maps.counters, &key, &key, sizeof(key)) == 0)
        if (bpf_map__lookup_elem(skel->maps.counters, &key, sizeof(key),
                                 counts, round_up(sizeof(uint64_t), 8) * ncpus, 0) == 0) {
            tcount = 0;
            for (size_t i = 0; i < ncpus; i++) tcount += counts[i];
            fwrite(&key, sizeof(uint32_t), 1, fp);
            fwrite(&tcount, sizeof(uint64_t), 1, fp);
        }
    fclose(fp);

cleanup:
    for (size_t i = 0; i < LINKS && links[i]; i+=2) {
        bpf_link__destroy(links[i]);
        bpf_link__destroy(links[i+1]);
    }
    if (pb) perf_buffer__free(pb);
    uprobe_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
