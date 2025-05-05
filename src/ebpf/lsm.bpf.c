#include "common_bpf.h"
#include "common.h"
#include "shared_map.h"

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



#define MAY_WRITE 0x0002


SEC("lsm/file_free_security")
int BPF_PROG(check_close_permission, struct file* file)
{
        struct inode*   inode;
        u64             ino_num;
        
        inode   = BPF_CORE_READ(file, f_inode);
        ino_num = BPF_CORE_READ(inode, i_ino);
        if (bpf_map_lookup_elem(&trap_ino_map, &ino_num)) {
                bpf_printk("trap.txt : lsm : write blocked");
                return -EPERM;
        }

}

SEC("lsm/file_permission")
int BPF_PROG(check_write_permission, struct file* file, int mask) 
{
        return 0;
        struct inode*   inode;
        u64             ino_num;
        
        inode   = BPF_CORE_READ(file, f_inode);
        ino_num = BPF_CORE_READ(inode, i_ino);
        

        if (!(mask & MAY_WRITE)) {
                return 0;
        }
        if (bpf_map_lookup_elem(&trap_ino_map, &ino_num)) {
                bpf_printk("trap.txt : lsm : write blocked");
                return -EPERM;
        }

        return 0;
}



char LICENSE[] SEC("license") = "GPL";
