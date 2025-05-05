#ifndef __MKTRAP_H__
#define __MKTRAP_H__


#define INODE_INFO_PATH "./inode_info.txt"
#define MKTRAP_PATH "./setup.py"
#define __MODE_DEBUG__


int create_symlink(const char* link_path);
int init_trap_ino_map (int map_fd);
int reinit_trap_ino_map (int map_fd);


#endif