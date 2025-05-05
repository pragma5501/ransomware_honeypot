import os
import shutil

CUR_TRAP_PATH = "./honeypot"
ROOT_TEAP_PATH = "/honeypot"
def check_root_permission():
    print(f"Effective UID: {os.geteuid()}")
    if os.geteuid() != 0:
        print("Permission Denied\n")
        exit()


def create_trap():
    try:
        if os.path.exists(ROOT_TEAP_PATH):
            shutil.rmtree(ROOT_TEAP_PATH)
            print("rm -rf %s", ROOT_TEAP_PATH)
        os.makedirs(ROOT_TEAP_PATH)

        if not os.path.exists(CUR_TRAP_PATH):
            print(f"{CUR_TRAP_PATH} doesn't exist")
            exit()
        
        for filename in os.listdir(CUR_TRAP_PATH):
            src_file = os.path.join(CUR_TRAP_PATH, filename)
            dst_file = os.path.join(ROOT_TEAP_PATH, filename)
            if os.path.isfile(src_file):
                shutil.copy2(src=src_file, dst=dst_file)
                print("copying", dst_file)
            
            if os.path.isfile(dst_file):
                os.chmod(dst_file, 0o666)

        #os.link(src="./trap.txt", dst="/root/.trap/trap.txt")

    except OSError as e:
        print(f"Cannot create trap Hard link \n{e}")
        exit()

def get_inode():
    ino_tbl = []
    try:
        for filename in os.listdir(ROOT_TEAP_PATH):
            src = os.path.join(ROOT_TEAP_PATH, filename)
            stat_info = os.stat(src)
            ino_tbl.append(stat_info.st_ino)
        
        return ino_tbl

    except OSError as e:
        print("Cannot read trap file")
        exit()

def append_inode_to__common_h(ino_tbl):
    with open("./inode_info.txt", "w") as f:
        for ino in ino_tbl:
            f.writelines(f"{ino}\n")
    
if __name__ == "__main__":
    check_root_permission()
    create_trap()

    ino_tbl = get_inode()
    append_inode_to__common_h(ino_tbl)
    print("Success\n")