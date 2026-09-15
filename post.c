#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "uprobe.h"

#define MAX_NAME  64
#define MAX_DEPTH 4096
#define MAX_EDGE  (FUNC + 1) * FUNC

struct map {
    uint32_t key;
    char name[MAX_NAME];
};

struct stack {
    uint32_t depth;
    uint32_t addrs[MAX_DEPTH];
};

struct edge {
    uint32_t caller;
    uint32_t callee;
    uint64_t count;
};

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
    struct map maps[FUNC] = {0};
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
            char *endp;
            errno = 0;
            maps[mi].key = strtoul(tok, &endp, 0);
            if (errno || endp == tok) {
                fprintf(stderr, "invalid key '%s' in mapping file\n", tok);
                fclose(fp);
                return 1;
            }
            strncpy(maps[mi].name, name, MAX_NAME);
            maps[mi].name[MAX_NAME - 1] = '\0';
            mi++;
            tok = strtok(NULL, " ");
        }
    }
    fclose(fp);
    if (mi == 0) {
        fprintf(stderr, "no mappings found in %s\n", argv[1]);
        return 1;
    }

    fp = fopen(RCOUF, "rb");
    if (!fp) {
        fprintf(stderr, "failed to fopen rcounts.txt\n");
        return 1;
    }
    uint64_t base;
    if (!fread(&base, sizeof(uint64_t), 1, fp)) {
        fprintf(stderr, "could not read binary base from rcounts.txt");
        return 1;
    }

    uint32_t key;
    uint64_t count;
    puts("----<function call counts>----");
    size_t rk, rc;
    while ((rk = fread(&key, sizeof(uint32_t), 1, fp)) == 1) {
        rc = fread(&count, sizeof(uint64_t), 1, fp);
        if (rc != 1) {
            fprintf(stderr, "warning: truncated record in rcounts.txt, ignoring\n");
            break;
        }

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
    uint8_t is_exit, exist;
    uint32_t cpu, ei = 0;
    struct stack st = {0};
    struct edge e, edges[MAX_EDGE] = {0};
    puts("\n----<entry and exit events>----");
    while (fread(&key, sizeof(uint32_t), 1, fp) == 1
           && fread(&cpu, sizeof(uint32_t), 1, fp) == 1) {
        is_exit = key & 1;
        key = (key - (uint32_t)(base << 1)) >> 1;

        if (is_exit) { // remove from stack
            if (st.depth > 0) st.depth--;
        }

        else { // is entry, create edge or increment count
            e = (struct edge){ .caller = 0, .callee = key, .count = 1 };
            if (st.depth > 0) // has caller
                e.caller = st.addrs[st.depth - 1];

            exist = 0;
            for (uint32_t i = 0; i < ei; i++)
                if (edges[i].caller == e.caller && edges[i].callee == e.callee) {
                    exist = 1;
                    edges[i].count++;
                    break;
                }

            if (!exist) {
                if (ei >= MAX_EDGE) {
                    fprintf(stderr, "too many edges\n");
                    fclose(fp);
                    return 1;
                }
                edges[ei++] = e;
            }

            if (st.depth < MAX_DEPTH){ // add on stack
                st.addrs[st.depth++] = key;
            }
            else {
                fprintf(stderr, "call stack exceeded MAX_DEPTH (%d), aborting\n", MAX_DEPTH);
                fclose(fp);
                return 1;
            }
        }

        for (uint8_t i = 0; i < mi; i++)
            if (maps[i].key == key) {
                printf("%s %s on cpu=%"PRIu32"\n",
                       is_exit ? "EXIT " : "ENTER", maps[i].name, cpu);
                break;
            }
    }
    fclose(fp);
    
    puts("\n----<function graph>----");
    for (uint32_t i = 0; i < ei; i++) {
        if (edges[i].caller == 0)
            printf("*");
        else for (uint8_t j = 0; j < mi; j++)
            if (maps[j].key == edges[i].caller) {
                printf("%s", maps[j].name);
            }

        for (uint8_t j = 0; j < mi; j++)
            if (maps[j].key == edges[i].callee) {
                printf(" --[%"PRIu64"]--> ", edges[i].count);
                printf("%s\n", maps[j].name);
            }
    }

    return 0;
}
