#ifndef UPROBE_H
#define UPROBE_H

#define REVF         "revents.txt"
#define RCOUF        "rcounts.txt"
#define RSTACK       "rstacks.txt"
#define MAX_LINE     1024
#define FUNC         32
#define MAX_DEPTH    1024
#define STACK_FRAMES 32

struct path_key {
    __u64 leaf;
    __u32 nframes;
    __u32 pad;
    __u64 frame[STACK_FRAMES];
};

struct flow {
    __u8   proto;
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
};

#endif
