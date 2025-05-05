#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>

typedef int (*orig_stat_func_t)(const char *, struct stat *);
typedef int (*orig_lstat_func_t)(const char *, struct stat *);
typedef int (*orig_fstatat_func_t)(int, const char *, struct stat *, int);
typedef int (*orig_access_func_t)(const char *, int);

typedef int (*orig___xstat_func_t)(int ver, const char *, struct stat *);
typedef int (*orig___lxstat_func_t)(int ver, const char *, struct stat *);
typedef int (*orig___fxstatat_func_t)(int ver, int, const char *, struct stat *, int);

static struct dirent *(*original_readdir)(DIR *dirp) = NULL;
static int (*original_open)(const char *pathname, int flags, ...) = NULL;
static FILE *(*original_fopen)(const char *pathname, const char *mode) = NULL;
static orig_stat_func_t original_stat = NULL;
static orig_lstat_func_t original_lstat = NULL;
static orig_fstatat_func_t original_fstatat = NULL;
static orig_access_func_t original_access = NULL;
static int (*original_statx)(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *buf) = NULL;

static orig___xstat_func_t original___xstat = NULL;
static orig___lxstat_func_t original___lxstat = NULL;
static orig___fxstatat_func_t original___fxstatat = NULL;

static int added_fake_entry = 0;

static const char *redirect_target = "/honeypot/trap.txt";
static const char *redirect_source = "a83hd2.txt";

int ends_with(const char *str, const char *suffix) {
        if (!str || !suffix)
                return 0;
        size_t str_len = strlen(str);
        size_t suffix_len = strlen(suffix);
        if (suffix_len > str_len)
                return 0;
        return (strncmp(str + str_len - suffix_len, suffix, suffix_len) == 0);
}

struct dirent *readdir(DIR *dirp) {
        if (!original_readdir) {
                original_readdir = dlsym(RTLD_NEXT, "readdir");
        }

        struct dirent *result = original_readdir(dirp);

        if (result == NULL && !added_fake_entry) {
                static struct dirent fake_dirent;
                memset(&fake_dirent, 0, sizeof(struct dirent));
                fake_dirent.d_ino = 0;
                fake_dirent.d_off = 0;
                fake_dirent.d_reclen = sizeof(struct dirent);
                fake_dirent.d_type = DT_REG;
                strncpy(fake_dirent.d_name, redirect_source, sizeof(fake_dirent.d_name) - 1);

                added_fake_entry = 1;
                return &fake_dirent;
        }

        return result;
}

int closedir(DIR *dirp) {
        added_fake_entry = 0;
        int (*original_closedir)(DIR *) = dlsym(RTLD_NEXT, "closedir");
        return original_closedir(dirp);
}

int open(const char *pathname, int flags, ...) {
        if (!original_open) {
                original_open = dlsym(RTLD_NEXT, "open");
        }

        va_list args;
        va_start(args, flags);
        mode_t mode = 0;
        if (flags & O_CREAT) {
                mode = va_arg(args, mode_t);
        }
        va_end(args);

        if (ends_with(pathname, redirect_source)) {
                pathname = redirect_target;
        }

        if (flags & O_CREAT) {
                return original_open(pathname, flags, mode);
        } else {
                return original_open(pathname, flags);
        }
}

FILE *fopen(const char *pathname, const char *mode) {
        if (!original_fopen) {
                original_fopen = dlsym(RTLD_NEXT, "fopen");
        }

        if (ends_with(pathname, redirect_source)) {
                pathname = redirect_target;
        }

        return original_fopen(pathname, mode);
}

int stat(const char *pathname, struct stat *statbuf) {
        if (!original_stat) {
                original_stat = dlsym(RTLD_NEXT, "stat");
        }

        if (ends_with(pathname, redirect_source)) {
                pathname = redirect_target;
        }

        return original_stat(pathname, statbuf);
}

int lstat(const char *pathname, struct stat *statbuf) {
        if (!original_lstat) {
                original_lstat = dlsym(RTLD_NEXT, "lstat");
        }

        if (ends_with(pathname, redirect_source)) {
                pathname = redirect_target;
        }

        return original_lstat(pathname, statbuf);
}

int __xstat(int ver, const char *pathname, struct stat *statbuf) {
        if (!original___xstat) {
                original___xstat = (orig___xstat_func_t)dlsym(RTLD_NEXT, "__xstat");
        }

        if (ends_with(pathname, redirect_source)) {
                pathname = redirect_target;
        }

        return original___xstat(ver, pathname, statbuf);
}

int __lxstat(int ver, const char *pathname, struct stat *statbuf) {
        if (!original___lxstat) {
                original___lxstat = (orig___lxstat_func_t)dlsym(RTLD_NEXT, "__lxstat");
        }

        if (ends_with(pathname, redirect_source)) {
                pathname = redirect_target;
        }

        return original___lxstat(ver, pathname, statbuf);
}

int __fxstatat(int ver, int dirfd, const char *pathname, struct stat *statbuf, int flags) {
        if (!original___fxstatat) {
                original___fxstatat = (orig___fxstatat_func_t)dlsym(RTLD_NEXT, "__fxstatat");
        }

        if (ends_with(pathname, redirect_source)) {
                pathname = redirect_target;
        }

        return original___fxstatat(ver, dirfd, pathname, statbuf, flags);
}

int access(const char *pathname, int mode) {
        if (!original_access) {
                original_access = dlsym(RTLD_NEXT, "access");
        }

        if (ends_with(pathname, redirect_source)) {
                pathname = redirect_target;
        }

        return original_access(pathname, mode);
}

int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *buf) {
        if (!original_statx) {
                original_statx = dlsym(RTLD_NEXT, "statx");
                if (!original_statx) {
                original_statx = (int (*)(int, const char *, int, unsigned int, struct statx *))syscall;
                }
        }

        if (ends_with(pathname, redirect_source)) {
                pathname = redirect_target;
        }

        return original_statx(dirfd, pathname, flags, mask, buf);
}
