#ifndef __COMMON_H__
#define __COMMON_H__

#define EPERM 1

#define RB_EVENT_TYPE_CLOSE  0x0
#define RB_EVENT_TYPE_OPENAT 0x1
#define RB_EVENT_TYPE_RENAME 0x2
#define RB_EVENT_TYPE_WRITE  0x3

#define HONEYPOT_PATH "/honeypot/trap.txt"

struct rb_event {
    __u8  event_type;
    __u32 pid;
    int   fd;
    __u64 ino_num;
    int buf_num;
    int buf_order;
    int8_t buf[256];
};


struct value_ino_map_t {
    __u16 cnt;
};

struct data_t {
    char filename[50];
};

#endif

#define INO_TRAP_FILE 14159694
#define INO_TRAP 5768927