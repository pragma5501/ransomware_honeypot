MY_PATH="$HOME/Downloads/ransomwares/Royal"

sudo rm -rf "$MY_PATH/dummy"
. "$MY_PATH/generate_dummy.sh" "$MY_PATH/dummy" 10 10
strace -f -s 1000 -o "$MY_PATH/strace_royal.txt" "$MY_PATH/royal.elf" "$MY_PATH/dummy" -id 11111111111111111111111111111111
