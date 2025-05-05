#include "common_bpf.h"
#include "common.h"
#include "shared_map.h"

#define RINGBUF_SIZE 1 << 24

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, RINGBUF_SIZE);
} rb SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1024);
        __type(key, u32);
        __type(value, struct data_t);
} openat_map SEC(".maps");


static __always_inline u64 get_openat_map_key (u32 pid, u32 fd) {
        return ((u64)pid << 32) + fd;
}

SEC("tracepoint/syscalls/sys_enter_getdents64")
int tracepoint__syscalls__sys_enter_getdents64 (
        struct trace_event_raw_sys_enter* ctx)
{
        int fd = (int)ctx->args[0];
        bpf_printk("getd_t : %d", fd);
}


SEC("tracepoint/syscalls/sys_enter_rename")
int tracepoint__syscalls__sys_enter_rename (struct trace_event_raw_sys_enter* ctx) 
{
        const char* oldpath = (const char *)ctx->args[0];
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        

        struct rb_event evt = {
                .event_type = RB_EVENT_TYPE_RENAME,
                .pid = pid,
        };
        bpf_probe_read_str(evt.buf, sizeof(evt.buf), oldpath);


        struct rb_event *rb_evt = bpf_ringbuf_reserve(&rb, sizeof(evt), 0);
        if (!rb_evt) {
                bpf_printk("[BAD] : Reserve Ringbuffer");
                return 0;
        }

        __builtin_memcpy(rb_evt, &evt, sizeof(evt));
        bpf_ringbuf_submit(rb_evt, 0);
        
        return 0;
}


SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve (struct trace_event_raw_sys_enter *ctx) 
{
        struct proc_info_t p_info = {}; 
        u32 pid = bpf_get_current_pid_tgid() >> 32;

        p_info.flag__syscall_stat = FLAG_OFF;
        p_info.count = 0;
        
        int err = bpf_map_update_elem(&execve_map, &pid, &p_info, 0);
        if (err < 0) {
                //bpf_printk("[ BAD ] : Update Execve Map Element : PID %d", pid);
                return 0;
        }
        //bpf_printk("[ OK ]  : Update Execve Map Element: PID %d", pid);
        return 0;
}

static __always_inline int trace_exit_proc (struct trace_event_raw_sys_enter *ctx)
{
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        
        int err = bpf_map_delete_elem(&execve_map, &pid);
        if (err < 0) {
                //bpf_printk("[ BAD ] : Delete Execve Map Element : PID %d", pid);
                return 0;
        }

        //bpf_printk("[ OK ]  : Delete Execve Map element : PID %d", pid);
        return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit")
int tracepoint__syscalls__sys_enter_exit (struct trace_event_raw_sys_enter *ctx) 
{
        return trace_exit_proc(ctx);
}

SEC("tracepoint/syscalls/sys_enter_exit_group")
int tracepoint__syscalls__sys_enter_exit_group (struct trace_event_raw_sys_enter *ctx) 
{
        return trace_exit_proc(ctx);
}



SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat (struct trace_event_raw_sys_enter *ctx)
{
        u32 fd           = (int)ctx->args[0];
        const char* path = (const char*)ctx->args[1];
        int flags        = (int)ctx->args[2];
        u64 pid_tgid     = bpf_get_current_pid_tgid();


        if (flags & O_DIRECTORY) {
                return 0;
        }

        return 0;
        struct data_t data;
        bpf_probe_read_str(data.filename, sizeof(data.filename), path);
        if (!bpf_strncmp(data.filename, sizeof(HONEYPOT_PATH), HONEYPOT_PATH)) {
                bpf_map_update_elem(&openat_map, &pid_tgid, &data, BPF_ANY);
                
                #ifdef DEBUG
                if (!bpf_map_lookup_elem(&openat_map, &pid_tgid)) 
                        return 0;
                bpf_printk("trap.txt test");
                #endif   
        }

    
        return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat (struct trace_event_raw_sys_exit *ctx)
{
        u32 fd          = ctx->ret;
        u64 pid_tgid    = bpf_get_current_pid_tgid();
        u32 pid         = pid_tgid >> 32;

        

        return 0;
}

static __always_inline int submit_rb_event (struct rb_event* e)
{
        struct rb_event *rb_evt = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
        if (!rb_evt) {
                bpf_printk("[BAD] : Reserve Ringbuffer");
                return -1;
        }

        __builtin_memcpy(rb_evt, e, sizeof(*e));
        bpf_ringbuf_submit(rb_evt, 0);
        return 0;
}

static __always_inline u64 get_inode_num (u32 fd)
{
        struct task_struct*     task;
        struct files_struct*    files;
        struct fdtable*         fdt;
        struct file**           fd_ptr;
        struct file*            file;
        struct dentry*          dentry;
        struct inode*           inode;

        u64                     ino_num;

        task    = (struct task_struct *)bpf_get_current_task();
        files   = BPF_CORE_READ(task, files);
        fdt     = BPF_CORE_READ(files, fdt);
        fd_ptr  = BPF_CORE_READ(fdt, fd);
        bpf_probe_read(&file, sizeof(file), &fd_ptr[fd]);

        inode   = BPF_CORE_READ(file, f_inode);
        ino_num = BPF_CORE_READ(inode, i_ino);

        return ino_num;
}

SEC("tracepoint/syscalls/sys_enter_write")
int tracepoint__syscalls__sys_enter_write (struct trace_event_raw_sys_enter* ctx) 
{
        u32 fd = (int)ctx->args[0];
        u64 size = (u64)ctx->args[2];
        u32 pid = bpf_get_current_pid_tgid() >> 32;

        u64 ino_num = get_inode_num(fd);
        if (!bpf_map_lookup_elem(&trap_ino_map, &ino_num)) {
                return 0;
        }

        u64 cur_size = size;
        u64 loop_cnt = (size / 256) + 1;

        if (loop_cnt > 20) {
                loop_cnt = 20;
        }

        struct rb_event evt = {
                .event_type = RB_EVENT_TYPE_WRITE,
                .pid = pid,
                .fd  = fd,
                .ino_num = ino_num,
                .buf_num = loop_cnt - 1,
        };


        u8 buf[256];
        int i;
        bpf_for(i, 0, loop_cnt) {
                evt.buf_order = i;
                bpf_core_read_user(evt.buf, sizeof(evt.buf), (const u8*)ctx->args[1] + 256 * i);
                evt.buf[256] = '\0';
                bpf_printk("trap.txt:buf %d : %s", i ,evt.buf);
                submit_rb_event(&evt);
        }

        bpf_printk("Permission Denied : cannot write /honeypot/trap.txt");
        return 0;
}


SEC("tracepoint/syscalls/sys_enter_open")
int tracepoint__syscalls__sys_enter_open (struct trace_event_raw_sys_enter *ctx)
{
        return 0;
}



static __always_inline int trace_stat (struct trace_event_raw_sys_enter *ctx)
{
        struct proc_info_t* p_info;
        u32 pid = bpf_get_current_pid_tgid() >> 32;

        p_info = bpf_map_lookup_elem(&execve_map, &pid);
        if (!p_info) {
                // bpf_printk("[ BAD ] : Lookup Execve Map Element : PID %d", pid);
                return 0;
        }

        if (p_info->flag__syscall_stat == FLAG_ON) {           
                return 0;
        }

        return 0;
}

SEC("tracepoint/syscalls/sys_enter_newstat")
int tracepoint__syscalls__sys_enter_newstat (struct trace_event_raw_sys_enter *ctx)
{
        return trace_stat(ctx);
}

SEC("tracepoint/syscalls/sys_enter_newfstatat")
int tracepoint__syscalls__sys_enter_newfstatat (struct trace_event_raw_sys_enter *ctx)
{
        return trace_stat(ctx);
}



SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint__syscalls__sys_enter_close (struct trace_event_raw_sys_enter *ctx)
{
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        int fd  = ctx->args[0];

        u64 key = get_openat_map_key(pid, fd);
        if (bpf_map_lookup_elem(&openat_map, &key)) {
                bpf_map_delete_elem(&openat_map, &key);
                bpf_printk("trap.txt : %d deleted", key);
        }

        struct task_struct*     task;
        struct files_struct*    files;
        struct fdtable*         fdt;
        struct file**           fd_ptr;
        struct file*            file;
        struct dentry*          dentry;
        struct inode*           inode;

        u64                     ino_num;

        task    = (struct task_struct *)bpf_get_current_task();
        files   = BPF_CORE_READ(task, files);
        fdt     = BPF_CORE_READ(files, fdt);
        fd_ptr  = BPF_CORE_READ(fdt, fd);
        bpf_probe_read(&file, sizeof(file), &fd_ptr[fd]);

        inode   = BPF_CORE_READ(file, f_inode);
        ino_num = BPF_CORE_READ(inode, i_ino);

        if ( ino_num != INO_TRAP ) {
                return 0;
        }
        bpf_printk("trap.txt write traffic");
        bpf_printk("trap.txt write : 0x%llx", key);
        struct rb_event evt = {
                .event_type = RB_EVENT_TYPE_CLOSE,
                .pid = pid,
                .fd  = fd,
                .ino_num = ino_num
        };

        struct rb_event *rb_evt = bpf_ringbuf_reserve(&rb, sizeof(evt), 0);
        if (!rb_evt) {
                bpf_printk("[BAD] : Reserve Ringbuffer");
                return 0;
        }

        __builtin_memcpy(rb_evt, &evt, sizeof(evt));
        bpf_ringbuf_submit(rb_evt, 0);

        return 0;
}




#define FLAG_MATCHED_FILENAME 1
#define FLAG_UNMATCHED_FILENAME 0

struct filename_data {
        const char *filename;
        const char *tgt;
        int match;
};

// Usage : bpf_loop ( #_iter, func_name, struct ctx, initial_idx )
static __always_inline int compare_path (void *ctx, int idx) 
{
        struct filename_data *data = ctx;
        if (data->filename[idx] != data->tgt[idx]) {
                data->match = FLAG_UNMATCHED_FILENAME;
                return 1;
        }
        if (data->tgt[idx] == '\0') {
                data->match = FLAG_MATCHED_FILENAME;
                return -1;
        }
        return 0;
}

struct st_bpf_strlen {
        const char* filename;
        int len;
};

// Usage : bpf_loop(PATH_MAX, )
static __always_inline int bpf_strlen (void *ctx, int idx)
{
        struct st_bpf_strlen *_ctx = ctx;
        if (_ctx->filename[idx] == '\0') {
                return -1; 
        }
        _ctx->len += 1;
        return 0;
}




char LICENSE[] SEC("license") = "GPL";