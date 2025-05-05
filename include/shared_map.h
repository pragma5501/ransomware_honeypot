#ifndef __SHARED_MAP_H__
#define __SHARED_MAP_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>



struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1024);
        __type(key, __u64);
        __type(value, __u8);
} trap_ino_map SEC(".maps");


#endif