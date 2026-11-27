#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/types.h>
#include <time.h>
#include <gelf.h>
#include <libelf.h>
#include "uprobe.h"

#define BINARY "/usr/local/bin/dpdk-testpmd"

#define MAX_NAME  64
#define MAX_EDGE  (FUNC * (FUNC - 1))

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

const char* get_name(uint32_t key, struct map *maps, uint8_t mi) {
    for (uint8_t i = 0; i < mi; i++) {
        if (maps[i].key == key) return maps[i].name;
    }
    return "unknown";
}

void print_tree(uint32_t current_caller, struct map *maps, uint8_t mi, struct edge *edges, uint32_t ei, int depth) {
    for (uint32_t i = 0; i < ei; i++) {
        if (edges[i].caller == current_caller) {
            for (int d = 0; d < depth; d++) {
                if (d == depth - 1) printf(" └── ");
                else printf("    ");
            }

            const char *callee_name = get_name(edges[i].callee, maps, mi);
            printf("%s (%.llu)\n", callee_name, (unsigned long long)edges[i].count);

            print_tree(edges[i].callee, maps, mi, edges, ei, depth + 1);
        }
    }
}

struct sym {
    uint64_t start;
    uint64_t size;
    char name[MAX_NAME];
};

struct cedge {
    uint64_t caller;
    uint64_t callee;
    uint64_t count;
};

int load_syms(const char *path, struct sym **out) {
    if (elf_version(EV_CURRENT) == EV_NONE) return -1;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        close(fd);
        return -1;
    }

    size_t n = 0, cap = 0;
    struct sym *syms = NULL;
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) == NULL) continue;
        if (shdr.sh_type != SHT_SYMTAB) continue;
        Elf_Data *data = elf_getdata(scn, NULL);
        if (!data) continue;
        size_t count = shdr.sh_entsize ? shdr.sh_size / shdr.sh_entsize : 0;
        for (size_t i = 0; i < count; i++) {
            GElf_Sym sym;
            if (gelf_getsym(data, (int)i, &sym) == NULL) continue;
            if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) continue;
            if (sym.st_value == 0 || sym.st_size == 0) continue;
            const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (!name || !name[0]) continue;
            if (n == cap) {
                cap = cap ? cap * 2 : 1024;
                struct sym *grown = realloc(syms, cap * sizeof(*syms));
                if (!grown) {
                    free(syms);
                    elf_end(elf);
                    close(fd);
                    return -1;
                }
                syms = grown;
            }
            syms[n].start = sym.st_value;
            syms[n].size = sym.st_size;
            strncpy(syms[n].name, name, MAX_NAME - 1);
            syms[n].name[MAX_NAME - 1] = '\0';
            n++;
        }
    }
    elf_end(elf);
    close(fd);
    *out = syms;
    return (int)n;
}

int find_sym(uint64_t off, struct sym *syms, int ns) {
    int best = -1;
    uint64_t best_sz = UINT64_MAX;
    for (int i = 0; i < ns; i++) {
        if (off >= syms[i].start && off < syms[i].start + syms[i].size &&
            syms[i].size < best_sz) {
            best = i;
            best_sz = syms[i].size;
        }
    }
    return best;
}

const char *sym_name(uint64_t start, struct sym *syms, int ns, struct map *maps, uint8_t mi) {
    for (int i = 0; i < ns; i++)
        if (syms[i].start == start) return syms[i].name;
    for (uint8_t i = 0; i < mi; i++)
        if (maps[i].key == start) return maps[i].name;
    return NULL;
}

int add_cedge(struct cedge **edges, int *n, int *cap, uint64_t caller, uint64_t callee, uint64_t count) {
    for (int i = 0; i < *n; i++) {
        if ((*edges)[i].caller == caller && (*edges)[i].callee == callee) {
            (*edges)[i].count += count;
            return 0;
        }
    }
    if (*n == *cap) {
        int ncap = *cap ? *cap * 2 : 64;
        struct cedge *grown = realloc(*edges, (size_t)ncap * sizeof(**edges));
        if (!grown) return -1;
        *edges = grown;
        *cap = ncap;
    }
    (*edges)[(*n)++] = (struct cedge){ .caller = caller, .callee = callee, .count = count };
    return 0;
}

int called_by_other(uint64_t id, struct cedge *edges, int n) {
    for (int i = 0; i < n; i++)
        if (edges[i].callee == id && edges[i].caller != id) return 1;
    return 0;
}

uint64_t sum_out(uint64_t id, struct cedge *edges, int n) {
    uint64_t c = 0;
    for (int i = 0; i < n; i++)
        if (edges[i].caller == id) c += edges[i].count;
    return c;
}

void print_branch(struct cedge *edges, int ne, struct sym *syms, int ns,
                  struct map *maps, uint8_t mi, uint64_t id, uint64_t count,
                  int depth, int *is_last, uint64_t *path, int plen) {
    for (int d = 0; d < depth; d++) {
        if (d == depth - 1) printf(is_last[d] ? " └── " : " ├── ");
        else printf(is_last[d] ? "     " : " │   ");
    }
    const char *name = sym_name(id, syms, ns, maps, mi);
    if (name) printf("%s (%llu)\n", name, (unsigned long long)count);
    else printf("%#" PRIx64 " (%llu)\n", id, (unsigned long long)count);

    for (int i = 0; i < plen; i++)
        if (path[i] == id) return;

    int nchild = 0;
    for (int i = 0; i < ne; i++)
        if (edges[i].caller == id) nchild++;

    path[plen] = id;
    int seen = 0;
    for (int i = 0; i < ne; i++) {
        if (edges[i].caller != id) continue;
        seen++;
        is_last[depth] = (seen == nchild);
        print_branch(edges, ne, syms, ns, maps, mi, edges[i].callee, edges[i].count,
                     depth + 1, is_last, path, plen + 1);
    }
}

void caller_graph(struct map *maps, uint8_t mi) {
    FILE *fp = fopen(RSTACK, "rb");
    if (!fp) return;

    uint64_t base;
    if (fread(&base, sizeof(base), 1, fp) != 1) {
        fprintf(stderr, "could not read binary base from rstacks.txt\n");
        fclose(fp);
        return;
    }

    struct sym *syms = NULL;
    int ns = load_syms(BINARY, &syms);
    if (ns < 0) {
        fprintf(stderr, "failed to read symbols from %s\n", BINARY);
        fclose(fp);
        return;
    }

    struct cedge *edges = NULL;
    int ne = 0, cap = 0;
    struct path_key pk;
    uint64_t count;
    while (fread(&pk, sizeof(pk), 1, fp) == 1 && fread(&count, sizeof(count), 1, fp) == 1) {
        if (pk.leaf < base) continue;
        uint32_t nframes = pk.nframes;
        if (nframes > STACK_FRAMES) nframes = STACK_FRAMES;

        uint64_t seq[STACK_FRAMES + 1];
        int ns_eq = 0;
        for (uint32_t i = 0; i < nframes; i++) {
            if (pk.frame[i] < base) break;
            int s = find_sym(pk.frame[i] - base, syms, ns);
            if (s < 0) break;
            seq[ns_eq++] = syms[s].start;
        }

        uint64_t ordered[STACK_FRAMES + 1];
        int no = 0;
        for (int i = ns_eq - 1; i >= 0; i--) ordered[no++] = seq[i];

        uint64_t leaf_off = pk.leaf - base;
        int ls = find_sym(leaf_off, syms, ns);
        ordered[no++] = ls >= 0 ? syms[ls].start : leaf_off;

        if (no == 1) {
            if (add_cedge(&edges, &ne, &cap, 0, ordered[0], count) != 0) {
                fprintf(stderr, "out of memory building caller graph\n");
                free(edges);
                free(syms);
                fclose(fp);
                return;
            }
        } else {
            for (int i = 0; i < no - 1; i++) {
                if (add_cedge(&edges, &ne, &cap, ordered[i], ordered[i + 1], count) != 0) {
                    fprintf(stderr, "out of memory building caller graph\n");
                    free(edges);
                    free(syms);
                    fclose(fp);
                    return;
                }
            }
        }
    }
    fclose(fp);

    puts("\n----<caller graph>----");
    uint64_t roots[1024];
    int nr = 0;
    for (int i = 0; i < ne; i++) {
        uint64_t id = edges[i].caller == 0 ? edges[i].callee : edges[i].caller;
        if (edges[i].caller != 0 && called_by_other(edges[i].caller, edges, ne)) continue;
        int seen = 0;
        for (int r = 0; r < nr; r++)
            if (roots[r] == id) seen = 1;
        if (seen || nr == 1024) continue;
        roots[nr++] = id;
    }
    int is_last[STACK_FRAMES + 2];
    uint64_t path[STACK_FRAMES + 2];
    for (int r = 0; r < nr; r++) {
        uint64_t count_r = 0;
        for (int i = 0; i < ne; i++) {
            if (edges[i].caller == 0 && edges[i].callee == roots[r]) count_r = edges[i].count;
        }
        if (count_r == 0) count_r = sum_out(roots[r], edges, ne);
        puts("");
        print_branch(edges, ne, syms, ns, maps, mi, roots[r], count_r, 0, is_last, path, 0);
    }

    free(edges);
    free(syms);
}

void print_graph(struct map *maps, uint8_t mi, struct edge *edges, uint32_t ei) {
    for (uint32_t i = 0; i < ei; i++) {
        if (edges[i].caller == 0) {
            puts("");
            const char *root_name = get_name(edges[i].callee, maps, mi);
            printf(" %s (%.llu)\n", root_name, (unsigned long long)edges[i].count);
            print_tree(edges[i].callee, maps, mi, edges, ei, 1);
        }
    }
}

int main(int argc, char **argv) {
    // read mappings from input file
    if (argc != 2) {
        fprintf(stderr, "usage: %s <function mappings file>\n", argv[0]);
        return 1;
    }
    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        fprintf(stderr, "failed to fopen %s\n", argv[1]);
        return 1;
    }
    struct map maps[FUNC] = {0};
    uint8_t mi = 0;
    char line[MAX_LINE], name[MAX_NAME], *tok, *endp;
    while (fgets(line, MAX_LINE, fp) && mi < FUNC) {
        line[strcspn(line, "\r\n")] = '\0';
        tok = strtok(line, " "); // name
        if (!tok) continue;
        strncpy(name, tok, MAX_NAME - 1);
        name[MAX_NAME - 1] = '\0';
        tok = strtok(NULL, " ");
        while (tok && mi < FUNC) {
            errno = 0;
            maps[mi].key = strtoul(tok, &endp, 0);
            if (errno || endp == tok) {
                fprintf(stderr, "invalid key '%s' in mapping file\n", tok);
                fclose(fp);
                return 1;
            }
            strncpy(maps[mi++].name, name, MAX_NAME);
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
    printf("%-35s | %-15s\n", "function", "calls");
    printf("--------------------------------------------------\n");

    while (fread(&key, sizeof(uint32_t), 1, fp) &&
               fread(&count, sizeof(uint64_t), 1, fp)) {
        key = (key - (uint32_t)(base << 1)) >> 1;
        for (uint8_t i = 0; i < mi; i++) {
            if (key == maps[i].key) {
                printf("%-35s | %" PRIu64 "\n", maps[i].name, count);
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

    uint64_t hdr[2];
    if (fread(hdr, sizeof(hdr), 1, fp) != 1) {
        fprintf(stderr, "could not read header from revents.txt\n");
        return 1;
    }
    int64_t off = (int64_t)(hdr[0] - hdr[1]);

    uint8_t is_exit, exist;
    uint32_t cpu, ei = 0;
    uint64_t ts;
    struct stack st = {0};
    struct edge e, edges[MAX_EDGE] = {0};
    puts("\n----<entry and exit events>----");
    while (fread(&key, sizeof(uint32_t), 1, fp) == 1
       && fread(&cpu, sizeof(uint32_t), 1, fp) == 1
       && fread(&ts, sizeof(uint64_t), 1, fp) == 1) {
        is_exit = key & 1;
        key = (key - (uint32_t)(base << 1)) >> 1;

        if (is_exit && st.depth > 0) // remove from stack
            st.depth--;

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

            if (!exist)
                edges[ei++] = e;

            if (st.depth < MAX_DEPTH) // add on stack
                st.addrs[st.depth++] = key;
            else {
                fprintf(stderr, "call stack exceeded MAX_DEPTH (%d), aborting\n", MAX_DEPTH);
                fclose(fp);
                return 1;
            }
        }

        for (uint8_t i = 0; i < mi; i++)
            if (maps[i].key == key) {
                uint64_t utc = ts + off;
                time_t sec = (time_t)(utc / 1000000000ULL);
                struct tm tm;
                char tbuf[32];
                gmtime_r(&sec, &tm);
                strftime(tbuf, sizeof tbuf, "%Y-%m-%dT%H:%M:%S", &tm);
                printf("[%s.%09"PRIu64"Z] %s %s on cpu=%"PRIu32"\n",
                    tbuf, (uint64_t)(utc % 1000000000ULL),
                    is_exit ? "EXIT " : "ENTER", maps[i].name, cpu);
                break;
            }
    }
    fclose(fp);

    puts("\n----<function graph>----");
    print_graph(maps, mi, edges, ei);
    caller_graph(maps, mi);

    return 0;
}
