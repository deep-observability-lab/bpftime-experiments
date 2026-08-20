#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "uprobe.h"

#define MAX_PATH 64
#define MAX_NAME 256
#define MAX_CMD  64

typedef struct {
    uint32_t key;
    char name[MAX_NAME];
} cache_entry;

static cache_entry cache[FUNC];
static uint8_t clen = 0;

int main() {
    // find pid
    FILE *fp = popen("pidof dpdk-testpmd", "r");
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
    char path[MAX_PATH], name[MAX_NAME], line[MAX_LINE];
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
        if (sscanf(line, "%lx-%*x %*s %*s %*s %*d %255s", &base, name) == 2
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

    fp = fopen(REVF, "rb");
    if (!fp) {
        fprintf(stderr, "failed to fopen revents.txt\n");
        return 1;
    }
    uint32_t key, cpu;
    char cmd[MAX_CMD];
    FILE *pp;
    // events
    uint8_t exit;
    uint8_t cached;
    uint8_t ci;
    while (fread(&key, sizeof(uint32_t), 1, fp) == 1
           && fread(&cpu, sizeof(uint32_t), 1, fp) == 1) {
        exit = key & 1;
        key = (key - (uint32_t)(base << 1)) >> 1;
        cached = 0;
        for (uint8_t i = 0; i < clen; i++)
            if (cache[i].key == key) {
                cached = 1;
                ci = i;
                break;
            }
        if (!cached) {
            snprintf(cmd, MAX_CMD, "addr2line -f -e %s 0x%x", BINARY, key);
            pp = popen(cmd, "r");
            if (!pp) {
                fprintf(stderr, "addr2line failed at 0x%"PRIx32"\n", key);
                continue;
            }
            if (!fgets(cache[clen].name, MAX_NAME, pp)) {
                fprintf(stderr, "could not read function name at 0x%"PRIx32"\n", key);
                pclose(pp);
                continue;
            }
            pclose(pp);
            cache[clen].name[strcspn(cache[clen].name, "\n")] = '\0';
            cache[clen].key = key;
            ci = clen++;
        }
        if (strcmp(cache[ci].name, "??") == 0) {
            fprintf(stderr, "could not find function name at 0x%"PRIx32"\n", key);
            continue;
        }
        printf("%s %s on cpu=%d\n", exit ? "EXIT " : "ENTER", cache[ci].name, cpu);
    }
    fclose(fp);

    // counts
    uint64_t count;
    fp = fopen(RCOUF, "rb");
    if (!fp) {
        fprintf(stderr, "failed to fopen rcounts.txt\n");
        return 1;
    }
    puts("\n----<function call counts>----");
    while (fread(&key, sizeof(uint32_t), 1, fp) == 1
           && fread(&count, sizeof(uint64_t), 1, fp) == 1) {
        key = (key - (uint32_t)(base << 1)) >> 1;
        for (uint8_t i = 0; i < clen; i++)
            if (cache[i].key == key) {
                if (strcmp(cache[ci].name, "??") == 0) {
                    fprintf(stderr, "could not find function name at 0x%"PRIx32"\n", key);
                    break;
                }
                printf("%s: %"PRIu64"\n", cache[i].name, count);
                break;
            }
    }
    fclose(fp);
    return 0;
}
