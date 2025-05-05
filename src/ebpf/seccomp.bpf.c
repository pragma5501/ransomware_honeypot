
#include "common_bpf.h"
#include "common.h"


#define FILENAME "/honeypot/trap.txt"

#define __NR_openat     56
#define __NR_write      64

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 << 10);
} entropy_rb SEC(".maps");


struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1024);
        __type(key, u32);
        __type(value, u32);
} fd_map SEC(".maps");

SEC("seccomp")
int seccomp__honeypot_op(struct seccomp_data *ctx)
{
        if (ctx->nr == __NR_openat ) {
                const char *filename =  (const char *)ctx->args[1];
                char buf[125];
                bpf_probe_read_str(buf, sizeof(buf), filename);
                bpf_printk("seccomp %s\n", buf);
                if (bpf_strncmp(buf, sizeof(FILENAME), FILENAME)) {

                }
        }

        return 0;
}

