#include <linux/kprobes.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/uaccess.h>
#include <linux/file.h>
#include <linux/ptrace.h>
#include <linux/string.h>
#include <linux/namei.h>
#include <linux/stat.h>

// #define KPROBE_DEBUG 1

#define FAKE_FILE_NAME "a83hd2.txt"


#define FAKE_MAXENTRY 10000
static u64 table_fake_entry[FAKE_MAXENTRY] = {0};

static const char *redirect_tgt = "/honeypot/trap.txt";
static const char *redirect_src = "a83hd2.txt";

static struct filename *hp_filename;

inline int ends_with(const char *str, const char *suffix) 
{
        if (!str || !suffix)
                return 0;
        size_t str_len = strlen(str);
        size_t suffix_len = strlen(suffix);
        if (suffix_len > str_len)
                return 0;
        return (strncmp(str + str_len - suffix_len, suffix, suffix_len) == 0);
}


void close_fd(unsigned int fd) 
{
        struct file *filp;

        filp = fget(fd);
        if (!filp) {
                pr_err("Invalid file descriptor: %d\n", fd);
                return;
        }

        filp_close(filp, NULL);
        fput(filp);
}


static void set_fake_entry_flag(int pid) 
{
        int idx = pid / 64;
        int idx2 = pid % 64;
        table_fake_entry[idx] |= ((u64)0x1 << (idx2)); 
}

static void del_fake_entry_flag(int pid)
{
        int idx = pid / 64;
        int idx2 = pid % 64;
        table_fake_entry[idx] &= ~((u64)0x1 << (idx2));
}

static int get_fake_entry_flag(int pid)
{
        int idx = pid / 64;
        int idx2 = pid % 64;
        return (table_fake_entry[idx] >> (idx2)) & (u64)0x1; 
}

static int kp__pre_handler__iterate_dir(struct kprobe *p, struct pt_regs *regs)
{
        //if (current_uid().val != 1001) return 0;
        if (get_fake_entry_flag(current->pid)) return 0;
        
        struct file *file = (struct file *)regs->di;
        struct dir_context* ctx = (struct dir_context *)regs->si;
        if (!file || !ctx) {
                pr_err("Invalid file or dir_context pointer\n");
                return -EINVAL;
        }
        
        const char *f_name = "a83hd2.txt";
        if (!dir_emit(ctx, f_name, strlen(f_name), 12345, DT_REG)) {
                pr_err("Failed to emit fake entry\n");
                return -EINVAL;
        }
        set_fake_entry_flag(current->pid);
        return 0;
}

static int kp__pre_handler__sys_getdents64(struct kprobe *p, struct pt_regs *regs)
{
    return 0;
}

static int krp__handler__getdents(struct kretprobe_instance *rp, struct pt_regs *regs) 
{
        //del_fake_entry_flag(current->pid);
        return 0;
}



static int kp__pre_handler__sys_openat(struct kprobe *p, struct pt_regs *regs)
{
        return 0;
}

static int kp__pre_handler__do_sys_openat2(struct kprobe *p, struct pt_regs *regs)
{
        return 0;
}

struct krp_data_dso2 {
        int flag_honeypot;
        struct open_how *how;
};

static int krp__pre_handler__do_sys_openat2(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        struct krp_data_dso2 *data;
        data = (struct krp_data_dso2 *)ri->data;
        data->flag_honeypot = 0;
        data->how = (struct open_how *)regs->dx;

        //if (current_uid().val != 1001) return 0;
        char pathname[256];
        char __user *user_pathname = (char __user*)regs->si;

        if (copy_from_user(pathname, user_pathname, sizeof(pathname))) {
                #ifdef KPROBE_DEBUG
                pr_err("[ERR] : do_sys_open : cannot copy user pathname\n");
                #endif
                return 0;
        }

        if (!ends_with(pathname, redirect_src)) return 0;

        data->flag_honeypot = 1;

        return 0;
}


static int krp__handler__do_sys_openat2(struct kretprobe_instance *ri, struct pt_regs *regs) 
{
        struct krp_data_dso2 *data;
        data = (struct krp_data_dso2 *)ri->data;

        //if (current_uid().val != 1001) return 0;
        if (data->flag_honeypot == 0)  return 0;

        struct open_how *how = data->how;

	int fd = get_unused_fd_flags(how->flags);
	if (fd >= 0) {
		struct file *f = filp_open(redirect_tgt, O_RDWR, 0);
		if (IS_ERR(f)) {
			put_unused_fd(fd);
			fd = PTR_ERR(f);
		} else {
			fd_install(fd, f);
		}
	}

        close_fd(regs_return_value(regs));
        regs_set_return_value(regs, fd);


        return 0;
}

struct krp_data_sys_stat {
        int flag_hp;
        int dfd;
        unsigned flags;
        unsigned int mask;
        struct statx __user *buffer;
};
static int kp__pre_handler__x64_sys_statx(struct kprobe* p, struct pt_regs* regs)
{
        return 0;
}

static int krp__pre_handler__x64_sys_statx(struct kretprobe_instance* ri, struct pt_regs* regs)
{
        // struct krp_data_sys_stat *data;
        // data = (struct krp_data_sys_stat *)ri->data;
        // data->flag_hp = 0;

        // if (current_uid().val != 1001) return 0;
        // char filename[256];
        // char __user *user_filename = (char __user*)regs->si;

        // if (copy_from_user(filename, user_filename, sizeof(filename))) {
        //         #ifdef KPROBE_DEBUG
        //         pr_err("[ERR] : __x64_sys_stat : cannot copy user filename");
        //         #endif
        //         return 0;
        // }

        // if (!ends_with(filename, redirect_src)) return 0;

        // data->flag_hp = 1;
        // data->dfd = (int)regs->di;
        // data->flags = (unsigned)regs->dx;
        // data->mask = (unsigned int)regs->cx;
        // data->buffer = (struct statx __user *)regs->r8;

        return 0;
}

static int krp__handler__x64_sys_statx(struct kretprobe_instance* ri, struct pt_regs* regs)
{

        return 0;
}

static int krp__pre_handler__x64_sys_stat(struct kretprobe_instance* ri, struct pt_regs* regs)
{
        return 0;
}

static int krp__handler__x64_sys_stat(struct kretprobe_instance* ri, struct pt_regs regs)
{
        return 0;
}

static int kp__pre_handler__vfs_statx(struct kprobe *p, struct pt_regs* regs)
{
        //if (current_uid().val != 1001) return 0;

        struct filename* name = (struct filename *)regs->si;
        if (!ends_with(name->name, redirect_src)) return 0;

        regs->si = hp_filename;


        return 0;
}

static struct kprobe kp = {
        .symbol_name = "__x64_sys_getdents64",
        .pre_handler = kp__pre_handler__sys_getdents64,
};

static struct kprobe kp_iter_dir = {
        .symbol_name = "iterate_dir",
        .pre_handler = kp__pre_handler__iterate_dir,
};

static struct kprobe kp_openat = {
        .symbol_name = "__x64_sys_openat",
        .pre_handler = kp__pre_handler__sys_openat,
};

static struct kprobe kp_do_sys_openat2 = {
        .symbol_name = "do_sys_openat2",
        .pre_handler = kp__pre_handler__do_sys_openat2,
};

static struct kprobe kp_vfs_statx = {
        .symbol_name = "vfs_statx",
        .pre_handler = kp__pre_handler__vfs_statx,
};

static struct kretprobe ret_kp = {
        .kp.symbol_name = "__x64_sys_getdents64",
        .handler        = krp__handler__getdents,
};

static struct kretprobe krp_do_sys_openat2 = {
        .kp.symbol_name = "do_sys_openat2",
        .entry_handler  = krp__pre_handler__do_sys_openat2,
        .handler        = krp__handler__do_sys_openat2, 
        .data_size      = sizeof(struct krp_data_dso2),
};

static struct kretprobe krp_statx = {
        .kp.symbol_name = "__x64_sys_statx",
        .entry_handler  = krp__pre_handler__x64_sys_statx,
        .handler        = krp__handler__x64_sys_statx,
        .data_size      = sizeof(struct krp_data_sys_stat),
};



static int init_variables(void)
{
        hp_filename = getname_kernel(redirect_tgt);
        if (IS_ERR(hp_filename)) {
                return -1;
        }
        pr_info("hpfilename : %s\n", hp_filename->name);
        return 0;
}

static void destroy_variables(void)
{
        putname(hp_filename);
}

static int __init kprobe_init(void)
{

        int ret;
        ret = init_variables();
        if (ret < 0) {
                pr_err("[ERR] : cannot get /honeypot/honeypot.txt filename\n");
                return ret;
        }


        ret = register_kprobe(&kp);
        if (ret < 0) {
                pr_err("[ERR] : register_kprobe\n");
                return ret;
        }

        ret = register_kprobe(&kp_iter_dir);
        if (ret < 0) {
                pr_err("[ERR] : register_kprobe 1\n");
                return ret;
        }

        ret = register_kprobe(&kp_openat);
        if (ret < 0) {
                pr_err("[ERR] : register_kprobe 2\n");
                return ret;
        }

        ret = register_kprobe(&kp_do_sys_openat2);
        if (ret < 0) {
                pr_err("[ERR] : register_kprobe 3\n");
                return ret;
        }

        ret = register_kprobe(&kp_vfs_statx);
        if (ret < 0) {
                pr_err("[ERR] : register_kprobe 4\n");
                return ret;
        }

        ret = register_kretprobe(&krp_do_sys_openat2);
        if (ret < 0) {
                pr_err("[ERR] : register_kretprobe 1\n");
                return ret;
        }
        

        ret = register_kretprobe(&ret_kp);
        if (ret < 0) {
                pr_err("[ERR] : register_kretprobe 2\n");
                return ret;
        }
        ret = register_kretprobe(&krp_statx);
        if (ret < 0) {
                pr_err("[ERR] : register_kretprobe 3\n");
                return ret;
        }

        pr_info("kprobe registered!\n");
        return 0;
}

static void __exit kprobe_exit(void)
{
        unregister_kprobe(&kp);
        unregister_kprobe(&kp_iter_dir);
        unregister_kprobe(&kp_openat);
        unregister_kprobe(&kp_do_sys_openat2);
        unregister_kprobe(&kp_vfs_statx);
        unregister_kretprobe(&krp_do_sys_openat2);
        unregister_kretprobe(&ret_kp);
        unregister_kretprobe(&krp_statx);

        destroy_variables();

        pr_info("kprobe unregistered!\n");
}


module_init(kprobe_init);
module_exit(kprobe_exit);


MODULE_LICENSE("GPL");


// SECTION : copy of inline or static kernel function

int copy_getname_statx_lookup_flags(int flags)
{
	int lookup_flags = 0;

	if (!(flags & AT_SYMLINK_NOFOLLOW))
		lookup_flags |= LOOKUP_FOLLOW;
	if (!(flags & AT_NO_AUTOMOUNT))
		lookup_flags |= LOOKUP_AUTOMOUNT;
	if (flags & AT_EMPTY_PATH)
		lookup_flags |= LOOKUP_EMPTY;

	return lookup_flags;
}