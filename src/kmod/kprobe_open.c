#include <linux/kprobes.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/uaccess.h>

#include <linux/ptrace.h>


static struct kprobe kp = {
        .symbol_name = "__x64_sys_openat",
        .pre_handler = handler_pre,
};


static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
        (const char __)regs->di;
}

static int __init kprobe_init(void)
{
        int ret;
        ret = register_kprobe(&kp);
        if (ret < 0) {
                pr_err("openat register_kprobe failed\n");
                return ret;
        }

        pr_info("openat kprobe registered!\n");
        return 0;
}

static void __exit kprobe_exit(void)
{
        unregister_kprobe(&kp);
        unregister_kprobe(&kp_iter_dir);
        pr_info("kprobe unregistered!\n");
}
