
import os
import sys
import time

from bcc import BPF

if not BPF.support_lsm():
        print("LSM not supported")

prog = """
#include <uapi/asm-generic/errno-base.h>
LSM_PROBE(bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    bpf_trace_printk("LSM BPF hook Worked");
    return -EPERM;
}
"""

b = BPF(text=prog)

while True:
    b.trace_print()