#include "common_bpf.h"
#include "common.h"

#define INO_RANSOMWARE_TRAP INO_TRAP
SEC("kprobe/ext4_readdir")
int kprobe__ext4_readdir(struct pt_regs *ctx)
{
        return 0;
}



SEC("kprobe/__x64_sys_getdents64")
int BPF_KPROBE (kprobe__x64_sys_getdents64, int fd,
        struct linux_dirent64 *dirent, unsigned int count) {
        bpf_printk("getd_count : %d\n", (int)PT_REGS_PARM1_CORE_SYSCALL(ctx));
        
        return 0;
}

static __always_inline int kprobe_open (struct pt_regs *ctx)
{
        return 0;

        int flags = PT_REGS_PARM3(ctx);

        if(!(flags & O_DIRECTORY)) {
                return 0;
        }

        // bpf_printk("/proc/ : kprobe directory");
        return 0;
}


SEC("kprobe/__x64_sys_openat")
int kprobe__x64_sys_openat(struct pt_regs *ctx)
{
        return kprobe_open(ctx);
}

SEC("kprobe/__x64_sys_openat2")
int kprobe__x64_sys_openat2(struct pt_regs *ctx)
{
        return kprobe_open(ctx);
}

SEC("kprobe/__x64_sys_open")
int kprobe__x64_sys_open(struct pt_regs *ctx)
{
        return kprobe_open(ctx);
}

SEC("kprobe/do_sys_open")
int kprobe__do_sys_open(struct pt_regs *ctx)
{
        return kprobe_open(ctx);
}

static __always_inline int kprobe_fsync (struct pt_regs *ctx) 
{
        int _fd = PT_REGS_PARM1(ctx);
        struct task_struct*     task;
        struct files_struct*    files;
        struct fdtable*         fdt;
        struct file**           fd_ptr;
        struct file*            file;
        struct dentry*          dentry;
        struct inode*           inode;

        ino_t inode_number;

        task = (struct task_struct*)bpf_get_current_task();

        // hmm..
        files           = BPF_CORE_READ(task, files);
        fdt             = BPF_CORE_READ(files, fdt);
        fd_ptr          = BPF_CORE_READ(fdt, fd);

        if (!fd_ptr) {
                return 0;
        }

        bpf_core_read(&file, sizeof(*file), &fd_ptr[_fd]);

        if (!file) return 0;

        dentry          = BPF_CORE_READ(file, f_path.dentry);
        inode           = BPF_CORE_READ(dentry, d_inode);
        inode_number    = BPF_CORE_READ(inode, i_ino);

        if (inode_number == INO_TRAP_FILE) {
                // Block close syscall
                return -1;
        }

        return 0;
} 

SEC("kprobe/__x64_sys_fdatasync")
int kprobe__x64_sys_fdatasync (struct pt_regs *ctx)
{
        return 0; //kprobe_fsync(ctx);
}

SEC("kprobe/__x64_sys_fsync")
int kprobe__x64_sys_fsync (struct pt_regs *ctx)
{
        return 0; //kprobe_fsync(ctx);
}

SEC("kprobe/__x64_sys_close")
int kprobe__x64_sys_close (struct pt_regs *ctx) 
{
        return 0;
}

SEC("kprobe/__x64_sys_write")
int kprobe__x64_sys_write (struct pt_regs *ctx)
{
        return 0;
}

char LICENSE[] SEC("license") = "GPL";