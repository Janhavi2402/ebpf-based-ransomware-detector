# src/loader.py
#!/usr/bin/env python3
from bcc import BPF
import ctypes
#comment 
import os
from datetime import datetime 

# Load eBPF C file
b = BPF(src_file=os.path.join(os.path.dirname(__file__), "monitor_ebpf.c"))

# Mirror of struct data_t in C
class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint),
        ("comm", ctypes.c_char * 16),          # TASK_COMM_LEN
        ("filename", ctypes.c_char * 256),
        ("syscall", ctypes.c_int),
        ("fd", ctypes.c_int),
        ("count", ctypes.c_ulonglong),
    ]

log_path = os.path.join(os.path.dirname(__file__), "..", "logs", "events.log")
os.makedirs(os.path.dirname(log_path), exist_ok=True)

def log_line(s: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {s}"
    print(line)
    with open(log_path, "a") as f:
        f.write(line + "\n")

def handle_event(cpu, data, size):
    evt = ctypes.cast(data, ctypes.POINTER(Data)).contents
    comm = evt.comm.split(b'\x00', 1)[0].decode(errors="replace")
    filename = evt.filename.split(b'\x00', 1)[0].decode(errors="replace")

    if evt.syscall == 1:
        # openat
        log_line(f"OPEN  pid={evt.pid:5d} comm={comm:<15} file='{filename}'")
    elif evt.syscall == 2:
        # write
        if filename:
            # (we keep empty for write; just in case)
            extra = f" file='{filename}'"
        else:
            extra = ""
        log_line(f"WRITE pid={evt.pid:5d} comm={comm:<15} fd={evt.fd} bytes={evt.count}{extra}")
    elif evt.syscall == 3:
        # unlinkat
        log_line(f"UNLINK pid={evt.pid:5d} comm={comm:<15} file='{filename}'")
    else:
        log_line(f"UNKNOWN pid={evt.pid} comm={comm} syscall={evt.syscall} file='{filename}'")

# Subscribe to perf buffer
b["events"].open_perf_buffer(handle_event)

print("🔍 Monitoring: openat, write, unlinkat (Ctrl+C to stop)\n")
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n✅ Stopped. Logs saved to logs/events.log")

