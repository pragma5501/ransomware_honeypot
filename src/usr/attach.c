
#include "tracepoint.skel.h"
#include "kprobe.skel.h"
#include "lsm.skel.h"
#include "maps.skel.h"



#include <stdlib.h>
#include <string.h>


typedef struct kprobe_bpf _kprb;
typedef struct tracepoint_bpf _trcpnt;

void *attach_shared_bpf_map () {
        struct maps_bpf* skel;
        skel = maps_bpf__open_and_load();

        if (!skel) {
                fprintf(stderr, "[INFO] : Open and Load \t[ BAD ] : maps\n");
                return (void*)0;
        }
        fprintf(stderr, "[INFO] : Open and Load \t[ OK ] : maps\n");

        int err = maps_bpf__attach(skel);
        if (err) {
                fprintf(stderr, "[INFO] : Attach\t[ Bad ] : maps\n");
                goto cleanup_maps;
        }
        fprintf(stderr, "[INFO] : Attach\t[ OK ] : maps\n");

        return (void*)skel;

cleanup_maps:
        maps_bpf__destroy(skel);
        return (void*)0;
}

void* attach_kprobe (struct maps_bpf *skel_maps) 
{
        struct kprobe_bpf* skel;
        skel = kprobe_bpf__open();

        if (!skel) {
                fprintf(stderr, "[INFO] : Open \t[ BAD ] : kprobe\n");
                return (void*)0;
        }
        fprintf(stderr, "[INFO] : Open \t[ OK ] : kprobe\n");

        // [[info]] : map fd synchronization start

        // int fd = bpf_map__fd(skel_maps->maps.trap_ino_map);
        // bpf_map__reuse_fd(skel->maps.trap_ino_map, fd);


        int err;
        err = kprobe_bpf__load(skel);
        if (err) {
                fprintf(stderr, "[INFO] : Load \t[ BAD ] : kprobe\n");
                return (void*)0;
        }
        fprintf(stderr, "[INFO] : Load \t[ OK ] : kprobe\n");


        err = kprobe_bpf__attach(skel);
        if (err) {
                fprintf(stderr, "[INFO] : Attach\t[ Bad ] : kprobe\n");
                goto cleanup_kprobe;
        }
        fprintf(stderr, "[INFO] : Attach\t[ OK ] : kprobe\n");

        return (void*)skel;

cleanup_kprobe:
        kprobe_bpf__destroy(skel);
        return (void*)0;
}


void* attach_tracepoint (struct maps_bpf *skel_maps)
{
        struct tracepoint_bpf* skel;
        skel = tracepoint_bpf__open();

        if (!skel) {
                fprintf(stderr, "[INFO] : Open \t[ BAD ] : tracepoint\n");
                return (void*)0;
        }
        fprintf(stderr, "[INFO] : Open \t[ OK ] : tracepoint\n");


        // [[info]] : map fd synchronization start

        // int fd = bpf_map__fd(skel_maps->maps.trap_ino_map);
        // bpf_map__reuse_fd(skel->maps.trap_ino_map, fd);
        
        int fd = bpf_map__fd(skel_maps->maps.trap_ino_map);
        bpf_map__reuse_fd(skel->maps.trap_ino_map, fd);

        // [[info]] : map fd synchronization done

        int err;
        err = tracepoint_bpf__load(skel);
        if (err) {
                fprintf(stderr, "[INFO] : Load \t[ BAD ] : tracepoint\n");
        }
        fprintf(stderr, "[INFO] : Load \t[ OK ] : tracepoint\n");


        err = tracepoint_bpf__attach(skel);
        if (err) {
                fprintf(stderr, "[INFO] : Attach\t[ Bad ] : tracepoint\n");
                goto cleanup_tracepoint;
        }
        fprintf(stderr, "[INFO] : Attach\t[ OK ] : tracepoint\n");

        return (void*)skel;

cleanup_tracepoint:
        tracepoint_bpf__destroy(skel);
        return (void*)0;
}



void* attach_lsm (struct maps_bpf *skel_maps)
{
        struct lsm_bpf* skel;
        skel = lsm_bpf__open();
        if (!skel) {
                fprintf(stderr, "[INFO] : Open \t[ BAD ] : lsm\n");
                return (void*)0;
        }
        fprintf(stderr, "[INFO] : Open \t[ OK ] : lsm\n");

        int fd = bpf_map__fd(skel_maps->maps.trap_ino_map);
        bpf_map__reuse_fd(skel->maps.trap_ino_map, fd);


        int err;
        err = lsm_bpf__load(skel);
        if (err) {
                fprintf(stderr, "[INFO] : Load \t[ BAD ] : lsm\n");
        }
        fprintf(stderr, "[INFO] : Load \t[ OK ] : lsm\n");


        err = lsm_bpf__attach(skel);
        if (err) {
                fprintf(stderr, "[INFO] : Attach\t[ Bad ] : lsm\n");
                goto cleanup_lsm;
        }
        fprintf(stderr, "[INFO] : Attach\t[ OK ] : lsm\n");

        return (void*)skel;

cleanup_lsm:
        lsm_bpf__destroy(skel);
        return (void*)0;
}
