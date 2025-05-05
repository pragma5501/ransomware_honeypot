#ifndef __ATTACH_H__
#define __ATTACH_H__

#include "maps.skel.h"

void *attach_shared_bpf_map ();
void* attach_kprobe (struct maps_bpf *skel_maps) ;
void* attach_tracepoint (struct maps_bpf *skel_maps);
void* attach_lsm (struct maps_bpf *skel_maps);
                         
#endif