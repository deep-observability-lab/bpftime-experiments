#ifndef UPROBE_H
#define UPROBE_H

#define FUNCS 32

struct event {
    __u32 key;
    __u8 is_exit;
};

#endif
