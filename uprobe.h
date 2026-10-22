#ifndef UPROBE_H
#define UPROBE_H

#define REVF     "revents.txt"
#define RCOUF    "rcounts.txt"
#define MAX_LINE 1024
#define FUNC     32

struct flow {
    __u8   proto;
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
};

#endif
