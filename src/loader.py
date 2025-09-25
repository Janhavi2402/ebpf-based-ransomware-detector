#!/usr/bin/env python3
# src/loader.py
from bcc import BPF
import ctypes, os, time, signal, sys
from datetime import datetime
from collections import deque, defaultdict

# -------------------------
# Load eBPF program (C)
# -------------------------
THIS_DIR = os.path.dirname(__file__)
BPF_C_FILE = os.path.join(THIS_DIR, "monitor_ebpf.c")

if not os.path.exists(BPF_C_FILE):
    print(f"Error: {BPF_C_FILE} not found!")
    sys.exit(1)

try:
    b = BPF(src_file=BPF_C_FILE)
except Exception as e:
    print("❌ Failed to load BPF program:", e)
    sys.exit(1)

# -------------------------
# Struct mirror
# -------------------------
class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 256),
        ("syscall", ctypes.c_int),
        ("fd", ctypes.c_int),
        ("count", ctypes.c_uint64),
    ]

# -------------------------
# Logs
# -------------------------
LOG_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "logs"))
os.makedirs(LOG_DIR, exist_ok=True)

EVENTS_LOG = os.path.join(LOG_DIR, "events.log")
ALERTS_LOG = os.path.join(LOG_DIR, "alerts.log")
ACTIONS_LOG = os.path.join(LOG_DIR, "actions.log")

for log in [EVENTS_LOG, ALERTS_LOG, ACTIONS_LOG]:
    with open(log, "w") as f:
        f.write(f"# {os.path.basename(log)} started {datetime.now()}\n")

def log_to(file_path, message, also_print=False):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {message}"
    if also_print:
        print(line)
    with open(file_path, "a") as f:
        f.write(line + "\n")
        f.flush()

# -------------------------
# Detection state
# -------------------------
WINDOW = 5
proc_stats = defaultdict(lambda: {"writes": deque(), "deletes": deque(), "bytes_written": deque()})

WRITE_THRESHOLD = 3
DELETE_THRESHOLD = 2
BYTES_THRESHOLD = 50 * 1024  # 50 KB

# -------------------------
# Kill switch
# -------------------------
def kill_process(pid, comm, reason):
    try:
        os.kill(pid, signal.SIGKILL)  # kill only the process, not group
        log_to(ACTIONS_LOG, f"[KILL] {comm} (pid={pid}) killed due to {reason}", also_print=True)
    except ProcessLookupError:
        log_to(ACTIONS_LOG, f"[MISS] {comm} (pid={pid}) not found for kill", also_print=True)
    except PermissionError:
        log_to(ACTIONS_LOG, f"[DENIED] Permission denied to kill {comm} (pid={pid})", also_print=True)
    except Exception as e:
        log_to(ACTIONS_LOG, f"[ERROR] Failed to kill {comm} (pid={pid}): {e}", also_print=True)


# -------------------------
# Detection check
# -------------------------
def check_alerts(pid, comm, filename=""):
    now = time.time()
    s = proc_stats[pid]

    while s["writes"] and now - s["writes"][0] > WINDOW:
        s["writes"].popleft()
    while s["deletes"] and now - s["deletes"][0] > WINDOW:
        s["deletes"].popleft()
    while s["bytes_written"] and now - s["bytes_written"][0][0] > WINDOW:
        s["bytes_written"].popleft()

    write_count = len(s["writes"])
    delete_count = len(s["deletes"])
    total_bytes = sum(x[1] for x in s["bytes_written"])

    if write_count >= WRITE_THRESHOLD:
        msg = f"[ALERT] {comm} (pid={pid}) wrote {write_count} files in {WINDOW}s"
        log_to(ALERTS_LOG, msg, also_print=True)
        kill_process(pid, comm, "excessive writes")

    if delete_count >= DELETE_THRESHOLD:
        msg = f"[ALERT] {comm} (pid={pid}) deleted {delete_count} files in {WINDOW}s"
        log_to(ALERTS_LOG, msg, also_print=True)
        kill_process(pid, comm, "excessive deletes")

    if total_bytes >= BYTES_THRESHOLD:
        msg = f"[ALERT] {comm} (pid={pid}) wrote {total_bytes/1024:.2f} KB in {WINDOW}s"
        log_to(ALERTS_LOG, msg, also_print=True)
        kill_process(pid, comm, "excessive bytes")

# -------------------------
# Event handler
# -------------------------
def handle_event(cpu, data, size):
    evt = ctypes.cast(data, ctypes.POINTER(Data)).contents
    comm = evt.comm.decode("utf-8", errors="replace").strip("\x00")
    filename = evt.filename.decode("utf-8", errors="replace").strip("\x00")
    now = time.time()

    if evt.syscall == 1:  # OPEN
        msg = f"OPEN   pid={evt.pid:5d} comm={comm:<15} file='{filename}'"
        print(msg)
        log_to(EVENTS_LOG, msg)
    elif evt.syscall == 2:  # WRITE
        msg = f"WRITE  pid={evt.pid:5d} comm={comm:<15} bytes={evt.count}"
        print(msg)
        log_to(EVENTS_LOG, msg)
        proc_stats[evt.pid]["writes"].append(now)
        proc_stats[evt.pid]["bytes_written"].append((now, evt.count))
        check_alerts(evt.pid, comm, filename)
    elif evt.syscall == 3:  # DELETE
        msg = f"DELETE pid={evt.pid:5d} comm={comm:<15} file='{filename}'"
        print(msg)
        log_to(EVENTS_LOG, msg)
        proc_stats[evt.pid]["deletes"].append(now)
        check_alerts(evt.pid, comm, filename)


# -------------------------
# Run loop
# -------------------------
print("🔍 Monitoring started. Press Ctrl+C to stop.\n")
print(f"📁 Events: {EVENTS_LOG}")
print(f"🚨 Alerts: {ALERTS_LOG}")
print(f"⚡ Actions: {ACTIONS_LOG}\n")

b["events"].open_perf_buffer(handle_event)

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("🛑 Stopped.")
