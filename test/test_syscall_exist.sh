cat /proc/kallsyms | grep getdents64
echo ----------------------
cat /proc/kallsyms | grep openat
echo ----------------------
cat /proc/kallsyms | grep _stat | grep sys