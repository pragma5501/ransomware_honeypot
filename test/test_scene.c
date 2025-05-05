#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>

int main(int argc, char *argv[]) {
    DIR *dir;
    struct dirent *entry;
    struct stat fileStat;
    char oldPath[1024], newPath[1024];


    if (argc != 2) {
        fprintf(stderr, "Usage: %s <directory>\n", argv[0]);
        return 1;
    }


    if ((dir = opendir(argv[1])) == NULL) {
        perror("opendir");
        return 1;
    }


    while ((entry = readdir(dir)) != NULL) {

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(oldPath, sizeof(oldPath), "%s/%s", argv[1], entry->d_name);


        if (stat(oldPath, &fileStat) == -1) {
            perror("stat");
            continue;
        }


        if (!S_ISDIR(fileStat.st_mode)) {
            snprintf(newPath, sizeof(newPath), "%s.tmp", oldPath);
            if (rename(oldPath, newPath) == -1) {
                perror("rename");
            } else {
                printf("Renamed %s to %s\n", oldPath, newPath);
            }
        }
    }

    // 디렉토리를 닫습니다.
    closedir(dir);
    return 0;
}
