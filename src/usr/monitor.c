#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <limits.h>

#include <bpf/libbpf.h>
#include "kprobe.skel.h"
#include "tracepoint.skel.h"
#include "lsm.skel.h"


#include "common.h"
#include "attach.h"
#include "mktrap.h"
#include "entropy.h"

static int libbpf_print_fn (enum libbpf_print_level level, const char* format, va_list args) 
{
        return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int (int signo)
{
        stop = 1;
}


#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

int handle_rb_event_rename (const struct rb_event *e) 
{
        int pid = (int)e->pid;
        char path[PATH_MAX];

        memcpy(path, e->buf, 256);
        return 0;
}

unsigned long freq[256] = {0};
static unsigned long entropy_size = 0;

#define LOCKED   1
#define UNLOCKED 0
uint8_t entrp_lock = UNLOCKED;
static int prev_buf_order = -1;

int handle_rb_event_write (const struct rb_event *e)
{
        if (e->buf_order != (prev_buf_order + 1)) 
                return 0;
        prev_buf_order += 1;
        if (e->buf_order == 0) {
                memset(freq, 0, sizeof(freq));
        }

        // get trap write buf
        uint8_t buf[256];
        memcpy(buf, e->buf, 256);
        fprintf(stderr, "write buf : %s\n", buf);
        
        uint8_t c;
        for (int i = 0; i < 256; i++) {
                
                c = buf[i];
                //if (c == EOF) break;
                freq[c]++;
                entropy_size++;
        }


        if (e->buf_order == e->buf_num) {
                double entropy = calculate_entropy(freq, entropy_size);
                fprintf(stderr, "ENTROPY : %lf\n",entropy );
                entropy_size = 0;
                prev_buf_order = -1;

                if (entropy < 7.0) {
                        return 0;
                }

                if (kill(e->pid, SIGKILL) == -1) {
                        perror("fucking Ransomware\n");
                        exit(EXIT_FAILURE);
                }
        }

        return 0;
}

int handle_rb_event_openat (const struct rb_event *e) 
{
        return 0;
}
 
static int handle_rb_event (void *ctx, void *data, size_t data_sz)
{
        const struct rb_event *e = data;
        switch(e->event_type) {
        case RB_EVENT_TYPE_CLOSE:
                break;
        case RB_EVENT_TYPE_OPENAT:
                handle_rb_event_openat(e);
                break;
        case RB_EVENT_TYPE_WRITE:
                handle_rb_event_write(e);
                break;
        }

        return 0;
}




int main (int argc, char** argv)
{
        int err;

        struct maps_bpf* skel_maps;
        struct kprobe_bpf* skel_kprobe;
        struct tracepoint_bpf* skel_tracepoint;
        struct lsm_bpf* skel_lsm;

        skel_maps = (struct maps_bpf*)attach_shared_bpf_map();
        if (!skel_maps) {
                goto cleanup;
        }
        skel_tracepoint = (struct tracepoint_bpf*)attach_tracepoint(skel_maps);
        if (!skel_tracepoint) {
                goto cleanup;
        }
        skel_kprobe = (struct kprobe_bpf*)attach_kprobe(skel_maps);
        if (!skel_kprobe) {
                goto cleanup;
        }
        skel_lsm = (struct lsm_bpf*)attach_lsm(skel_maps);
        if (!skel_lsm) {
                goto cleanup;
        }


        int rb_map_fd = bpf_map__fd(skel_tracepoint->maps.rb);
        
        int trap_ino_map_fd = bpf_map__fd(skel_maps->maps.trap_ino_map);
        err = init_trap_ino_map(trap_ino_map_fd);
        
        if (!err) {
                goto cleanup;
        }

        struct ring_buffer* rb = NULL;
        rb = ring_buffer__new(rb_map_fd, handle_rb_event, NULL, NULL);
        if (!rb) {
                fprintf(stderr, "[ ERR ] : Failed to create ring buffer\n");
                goto cleanup;
        }


        if (signal(SIGINT, sig_int) == SIG_ERR) {
                fprintf(stderr, "[ ERR ] : can't set signal handler %s\n", strerror(errno));
                goto cleanup;
        }
        
        while (!stop) {
                if (ring_buffer__poll(rb, 100) < 0)
                        break;
                // fprintf(stderr, ".");
        
        }
cleanup:

        fprintf(stderr, "[ ERR ] : cleanup ebpf\n");
        return 0;
}

