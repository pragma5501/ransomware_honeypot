#include "mktrap.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/wait.h>

#include "tracepoint.skel.h"
#include "kprobe.skel.h"
#include "maps.skel.h"

#include "common.h"


#define ROOT_TRAP_PATH "/root/trap/"

int create_symlink(const char* link_path)
{
        const char* root_path = ROOT_TRAP_PATH;

        int err;
        err = symlink(root_path, link_path);
        if (!err) {
                fprintf(stderr, "[ ERR ]  : Cannot Create Symlink");
        }

        printf("[ INFO ] : Symbolic link created %s -> %s\n", link_path, root_path);
        return 0;
}
int init_honeypot () 
{
        pid_t pid;
        int status;

        pid = fork();

        switch(pid) {
        case -1:
                return 1;
        case 0:
                execlp("python3", "python3", MKTRAP_PATH, (char *)NULL);
                return 1;
        default:
                waitpid(pid, &status, 0);
        }

        return 0;

}

int init_trap_ino_map (int map_fd)
{
        init_honeypot();
        
        FILE* fp = fopen(INODE_INFO_PATH, "r");
        if (fp == NULL) {
                fprintf(stderr, "[ ERR ]  : Cannot open %s\n", INODE_INFO_PATH);
        }

        char buf[24];
        __u64 key_ino;
        while (fgets(buf, sizeof(buf), fp)) {
                sscanf(buf, "%llu", &key_ino);

                struct value_ino_map_t value = {
                        .cnt = 1
                };

                int err;
                err = bpf_map_update_elem(map_fd, &key_ino, &value, BPF_ANY);
                if (err) {
                        fprintf(stderr, "[ ERR ] : Cannot init trap inode hash map\n");
                        return -1;
                }


                // Test : initializing ino map is well operated. 
                #ifdef __MODE_DEBUG__
                struct value_ino_map_t* test_value;
                test_value = malloc(sizeof(struct value_ino_map_t));

                err = bpf_map_lookup_elem(map_fd, &key_ino, test_value);
                if (err) {
                        fprintf(stderr, "[ ERR ] : Cannot look up trap inode\n");
                        return -1;
                }
                
                fprintf(stderr, "[TEST] : ino cnt %llu\n", test_value->cnt);
                
                fprintf(stderr, "[ OK ] : ino map works well (%llu)\n", key_ino);
                free(test_value);

                #endif
        }

        #ifdef __MODE_DEBUG__
        fprintf(stderr, "[ OK ] : Init inode hash map\n");
        #endif 
 
        return 1;
}

int free_trap_ino_map (int map_fd)
{
        FILE* fp = fopen(INODE_INFO_PATH, "r");
        if (fp == NULL) {
                fprintf(stderr, "[ ERR ]  : Cannot open %s\n", INODE_INFO_PATH);
        }

        char buf[24];
        __u64 key_ino;
        while (fgets(buf, sizeof(buf), fp)) {
                sscanf(buf, "%llu", &key_ino);

                int err;
                err = bpf_map_delete_elem(map_fd, &key_ino);
                if (err) {
                        fprintf(stderr, "[ ERR ] : Cannot init trap inode hash map\n");
                        return -1;
                }
        }
}

int reinit_trap_ino_map (int map_fd) 
{
        free_trap_ino_map(map_fd);
        init_trap_ino_map(map_fd);
}