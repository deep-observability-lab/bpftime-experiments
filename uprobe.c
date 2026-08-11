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

struct func {
    char name[MAX_NAME];
    size_t offsets[LINKS / 2];
    size_t count;
};

struct func funcs[FUNCS] = {0};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) { return vfprintf(stderr, format, args); }

static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

static void handle_event(void *ctx, int cpu, void *data, unsigned int size) {
    const struct event *e = (const struct event *)data;
    printf("%s %s on cpu=%d\n", e->is_exit ? "EXIT" : "ENTER", funcs[e->key].name, cpu);
}

int main(int argc, char **argv) {
    // read offsets from file
    if (argc != 2) {
        fprintf(stderr, "usage: %s funcs.conf\n", argv[0]);
        return 1;
    }
    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        perror("fopen");
        return 1;
    }
    char line[MAX_LINE], *token;
    size_t funci = 0;
    while (funci < FUNCS && fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        token = strtok(line, " \t");
        if (!token) break;
        strncpy(funcs[funci].name, token, MAX_NAME - 1);
        funcs[funci].name[MAX_NAME - 1] = '\0';
        while ((token = strtok(NULL, " \t")) && funcs[funci].count < LINKS / 2)
            funcs[funci].offsets[funcs[funci].count++] = strtoul(token, NULL, 0);
        funci++;
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

    for (size_t i = 0, j = 0; i < funci; i++) {
        DECLARE_LIBBPF_OPTS(bpf_uprobe_opts, opts, .bpf_cookie = i);
        for (size_t k = 0; k < funcs[i].count && j < LINKS / 2; k++, j++) {
            // counter + entry
            opts.retprobe = false;
            links[2*j] = bpf_program__attach_uprobe_opts(
                skel->progs.do_uprobe, -1, BINARY, funcs[i].offsets[k], &opts);
            if (!links[2*j]) {
                fprintf(stderr, "%s: Failed to attach uprobe\n", funcs[i].name);
                err = -1;
                goto cleanup;
            }
            // exit
            opts.retprobe = true;
            links[2*j+1] = bpf_program__attach_uprobe_opts(
                skel->progs.do_uretprobe, -1, BINARY, funcs[i].offsets[k], &opts);
            if (!links[2*j+1]) {
                fprintf(stderr, "%s: Failed to attach uretprobe\n", funcs[i].name);
                err = -1;
                goto cleanup;
            }
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
    for (uint32_t key = 0; key < funci; key++) {
        if (bpf_map__lookup_elem(skel->maps.counters, &key, sizeof(key),
                                 counts, round_up(sizeof(__u64), 8) * ncpus, 0) == 0) {
            tcount = 0;
            for (int cpui = 0; cpui < ncpus; cpui++) tcount += counts[cpui];
            printf("%s: %lu\n", funcs[key].name, tcount);
        }
    }
    for (size_t i = 0; i < LINKS && links[i]; i++) bpf_link__destroy(links[i]);
    if (pb) perf_buffer__free(pb);
    uprobe_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
