#ifndef __COMMON_BPF_H__
#define __COMMON_BPF_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

#define O_DIRECTORY 0x0200000
#define FLAG_OFF 0x0
#define FLAG_ON  0x1

#define DEBUG

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 10240);
        __type(key, u32);
        __type(value, u8); // trap dir count
} map_trap_cnt SEC(".maps");


struct proc_info_t {
        u8 flag__syscall_stat;
        u8 flag__syscall_clone;
        u8 count;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1024);
        __type(key, u32);
        __type(value, struct proc_info_t);
} execve_map SEC(".maps");




#endif