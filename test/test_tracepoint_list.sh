echo If you want to know what you are able to use at attaching \
    , edit below grep 

bpftrace -l 'tracepoint:syscalls:*' | grep sys
echo ----------------------
bpftrace -l 'kprobe:*' | grep sys