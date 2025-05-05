from bcc import BPF
import ctypes
import os



bpf_text = ""
with open("/home/os/code/ugrp/src/bpf_write.c") as f:
    bpf_text = f.read()

cflags = [
    "-Wimplicit-function-declaration"
]

b = BPF(text=bpf_text.replace('BPF_SID', str(os.getpid() + 1)), cflags=cflags)


class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("fd",  ctypes.c_uint64),
        ("comm", ctypes. c_char * 16),
        ("data", ctypes. c_char * 256)
    ]


def print_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    print(f"PID: {event.pid}, FD: {event.fd}, COMM: {event.comm.decode('utf-8', 'replace')}, DATA: {event.data.decode('utf-8', 'replace')}")

b["events"].open_perf_buffer(print_event)

print("Tracing...")

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()