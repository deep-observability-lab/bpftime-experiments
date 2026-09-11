#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include "uprobe.h"

#define MAX_NAME 64

typedef struct {
    uint32_t key;
    char name[MAX_NAME];
} map;

int main(int argc, char **argv) {
    // read mappings from input file
    if (argc != 2) {
        fprintf(stderr, "usage: %s <function mappings file>\n", argv[0]);
        return 1;
    }
    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        fprintf(stderr, "failed to fopen input file\n");
        return 1;
    }
    map maps[FUNC];
    uint8_t mi = 0;
    char line[MAX_LINE], name[MAX_NAME], *tok;
    while (fgets(line, MAX_LINE, fp) && mi < FUNC) {
        line[strcspn(line, "\r\n")] = '\0';
        tok = strtok(line, " "); // name
        if (!tok) continue;
        strncpy(name, tok, MAX_NAME - 1);
        name[MAX_NAME - 1] = '\0';
        tok = strtok(NULL, " ");
        while (tok && mi < FUNC) {
            maps[mi].key = strtoul(tok, NULL, 0);
            strncpy(maps[mi++].name, name, MAX_NAME);
            tok = strtok(NULL, " ");
        }
    }
    fclose(fp);

    fp = fopen(RCOUF, "rb");
    if (!fp) {
        fprintf(stderr, "failed to fopen rcounts.txt\n");
        return 1;
    }
    uint32_t base;
    if (!fread(&base, sizeof(uint64_t), 1, fp)) {
        fprintf(stderr, "could not read binary base from rcounts.txt");
        return 1;
    }

    uint32_t key;
    uint64_t count;
    puts("----<function call counts>----");
    while (fread(&key, sizeof(uint32_t), 1, fp) &&
           fread(&count, sizeof(uint64_t), 1, fp)) {
        key = (key - (uint32_t)(base << 1)) >> 1;
        for (uint8_t i = 0; i < mi; i++) {
            if (key == maps[i].key) {
                printf("%s: %"PRIu64"\n", maps[i].name, count);
                break;
            }
        }
    }
    fclose(fp);

    fp = fopen(REVF, "rb");
    if (!fp) {
        fprintf(stderr, "failed to fopen revents.txt\n");
        return 1;
    }
    uint8_t exit;
    uint32_t cpu;
    puts("\n----<entry and exit events>----");
    while (fread(&key, sizeof(uint32_t), 1, fp) == 1
           && fread(&cpu, sizeof(uint32_t), 1, fp) == 1) {
        exit = key & 1;
        key = (key - (uint32_t)(base << 1)) >> 1;
        for (uint8_t i = 0; i < mi; i++)
            if (maps[i].key == key) {
                printf("%s %s on cpu=%d\n", exit ? "EXIT " : "ENTER", maps[i].name, cpu);
                break;
            }
    }
    fclose(fp);

    return 0;
}
