#!/usr/bin/env python3
import os
import sys
import time
import signal
import ctypes
import json
from datetime import datetime
from collections import deque, defaultdict
from math import log2
from bcc import BPF

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

class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 256),
        ("syscall", ctypes.c_int),
        ("fd", ctypes.c_int),
        ("count", ctypes.c_uint64),
    ]

LOG_DIR = os.path.abspath(os.path.join(THIS_DIR, "..", "logs"))
os.makedirs(LOG_DIR, exist_ok=True)
EVENTS_LOG = os.path.join(LOG_DIR, "events.log")
ALERTS_LOG = os.path.join(LOG_DIR, "alerts.log")
ACTIONS_LOG = os.path.join(LOG_DIR, "actions.log")
FORENSIC_LOG = os.path.join(LOG_DIR, "forensic.jsonl")

for log in [EVENTS_LOG, ALERTS_LOG, ACTIONS_LOG, FORENSIC_LOG]:
    with open(log, "w") as f:
        f.write(f"# {os.path.basename(log)} started {datetime.now().isoformat()}\n")

def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_to(path, msg, print_out=False):
    line = f"[{now_ts()}] {msg}"
    if print_out:
        print(line)
    with open(path, "a") as f:
        f.write(line + "\n")
        f.flush()

def forensic_record(entry):
    with open(FORENSIC_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
        f.flush()

WINDOW = 10
proc_stats = defaultdict(lambda: {
    "writes": deque(),
    "deletes": deque(),
    "bytes_written": deque(),
    "files": deque(),
    "entropy_scores": deque()
})
global_writes = deque(maxlen=10000)
global_bytes = deque(maxlen=10000)

WRITE_THRESHOLD = 6
DELETE_THRESHOLD = 3
BYTES_THRESHOLD = 200 * 1024
ENTROPY_THRESHOLD = 7.5
QUARANTINE_SECONDS = 6

WHITELIST = {"systemd", "sshd", "journald", "rsyslogd", "dockerd", "init"}
SUSPICIOUS_EXT = {".locked", ".crypt", ".enc", ".encrypted", ".aes", ".lockedfile", ".locked~"}

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    length = len(data)
    for v in freq.values():
        p = v / length
        ent -= p * log2(p)
    return ent

def prune(pid):
    now = time.time()
    s = proc_stats[pid]
    while s["writes"] and now - s["writes"][0] > WINDOW:
        s["writes"].popleft()
    while s["deletes"] and now - s["deletes"][0] > WINDOW:
        s["deletes"].popleft()
    while s["bytes_written"] and now - s["bytes_written"][0][0] > WINDOW:
        s["bytes_written"].popleft()
    while s["files"] and now - s["files"][0][0] > WINDOW:
        s["files"].popleft()
    while s["entropy_scores"] and now - s["entropy_scores"][0][0] > WINDOW:
        s["entropy_scores"].popleft()

def zscore(value, seq):
    if not seq:
        return 0.0
    mean = sum(seq) / len(seq)
    var = sum((x - mean) ** 2 for x in seq) / len(seq)
    std = var ** 0.5
    if std == 0:
        return 0.0
    return (value - mean) / std

def gather_process_info(pid):
    info = {}
    try:
        info['cmdline'] = open(f"/proc/{pid}/cmdline", "rb").read().replace(b'\x00', b' ').decode(errors="replace").strip()
    except Exception:
        info['cmdline'] = None
    try:
        info['cwd'] = os.readlink(f"/proc/{pid}/cwd")
    except Exception:
        info['cwd'] = None
    try:
        info['exe'] = os.readlink(f"/proc/{pid}/exe")
    except Exception:
        info['exe'] = None
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("Uid:"):
                    info['uid'] = line.split()[1]
                if line.startswith("Ppid:"):
                    info['ppid'] = line.split()[1]
    except Exception:
        pass
    try:
        fds = []
        fd_dir = f"/proc/{pid}/fd"
        if os.path.isdir(fd_dir):
            for fdname in os.listdir(fd_dir):
                try:
                    link = os.readlink(f"{fd_dir}/{fdname}")
                    fds.append(link)
                except Exception:
                    pass
        info['fds'] = fds
    except Exception:
        info['fds'] = None
    return info

def stop_and_audit_then_kill(pid, comm, reason, evidence):
    try:
        os.kill(pid, signal.SIGSTOP)
        log_to(ACTIONS_LOG, f"[QUARANTINE] comm='{comm}' pid={pid} reason={reason}", True)
        info = gather_process_info(pid)
        forensic = {
            "timestamp": now_ts(),
            "pid": pid,
            "comm": comm,
            "reason": reason,
            "info": info,
            "evidence": evidence
        }
        forensic_record(forensic)
        time.sleep(QUARANTINE_SECONDS)
        try:
            os.kill(pid, signal.SIGKILL)
            log_to(ACTIONS_LOG, f"[KILL] comm='{comm}' pid={pid} final_action=SIGKILL", True)
        except ProcessLookupError:
            log_to(ACTIONS_LOG, f"[MISS] comm='{comm}' pid={pid} missing_before_kill", True)
    except PermissionError:
        log_to(ACTIONS_LOG, f"[DENIED] insufficient privileges to quarantine/kill pid={pid} comm={comm}", True)
    except ProcessLookupError:
        log_to(ACTIONS_LOG, f"[MISS] target process not found pid={pid} comm={comm}", True)
    except Exception as e:
        log_to(ACTIONS_LOG, f"[ERROR] stop/kill failed for pid={pid} comm={comm} err={e}", True)

def check_alerts(pid, comm):
    prune(pid)
    s = proc_stats[pid]
    write_count = len(s["writes"])
    delete_count = len(s["deletes"])
    total_bytes = sum(x[1] for x in s["bytes_written"])
    distinct_files = len({f for _, f in s["files"] if f})
    entropy_scores = [e for _, e in s["entropy_scores"]]
    max_entropy = max(entropy_scores) if entropy_scores else 0.0
    wc_z = zscore(write_count, list(global_writes)) if global_writes else 0.0
    reasons = []
    evidence = {
        "write_count": write_count,
        "delete_count": delete_count,
        "total_bytes": total_bytes,
        "distinct_files": distinct_files,
        "max_entropy": max_entropy,
        "recent_files": [f for _, f in list(s["files"])][-10:],
    }
    if comm in WHITELIST:
        return
    triggered = False
    if distinct_files >= WRITE_THRESHOLD:
        reasons.append("distinct_files")
        triggered = True
    if delete_count >= DELETE_THRESHOLD:
        reasons.append("delete_count")
        triggered = True
    if total_bytes >= BYTES_THRESHOLD:
        reasons.append("total_bytes")
        triggered = True
    if max_entropy >= ENTROPY_THRESHOLD:
        reasons.append("high_entropy")
        triggered = True
    if wc_z > 3.0:
        reasons.append("write_rate_anomaly")
        triggered = True
    if triggered:
        reason = ",".join(reasons)
        log_to(ALERTS_LOG, f"[ALERT] comm='{comm}' pid={pid} reasons={reason} evidence={json.dumps(evidence)}", True)
        stop_and_audit_then_kill(pid, comm, reason, evidence)

def attribute_recent_file(pid):
    s = proc_stats[pid]
    if s["files"]:
        return s["files"][-1][1]
    return ""

def handle_event(cpu, data, size):
    evt = ctypes.cast(data, ctypes.POINTER(Data)).contents
    comm = evt.comm.decode("utf-8", errors="replace").strip("\x00")
    filename = evt.filename.decode("utf-8", errors="replace").strip("\x00")
    pid = int(evt.pid)
    ts = time.time()
    if evt.syscall == 1:
        msg = f"OPEN   pid={pid:5d} comm={comm:<16} file='{filename}'"
        log_to(EVENTS_LOG, msg, True)
        if filename:
            proc_stats[pid]["files"].append((ts, filename))
    elif evt.syscall == 2:
        msg = f"WRITE  pid={pid:5d} comm={comm:<16} fd={evt.fd} bytes={evt.count}"
        log_to(EVENTS_LOG, msg, True)
        proc_stats[pid]["writes"].append(ts)
        proc_stats[pid]["bytes_written"].append((ts, int(evt.count)))
        global_writes.append(len(proc_stats[pid]["writes"]))
        global_bytes.append(int(evt.count))
        target = attribute_recent_file(pid)
        entropy_score = 0.0
        if target:
            try:
                if target.startswith("/"):
                    abspath = target
                else:
                    cwd = gather_process_info(pid).get('cwd') or "/"
                    abspath = os.path.join(cwd, target)
                with open(abspath, "rb") as f:
                    sample = f.read(4096)
                    entropy_score = shannon_entropy(sample)
            except Exception:
                entropy_score = 0.0
        proc_stats[pid]["entropy_scores"].append((ts, entropy_score))
        if target and any(target.lower().endswith(ext) for ext in SUSPICIOUS_EXT):
            proc_stats[pid]["files"].append((ts, target))
        check_alerts(pid, comm)
    elif evt.syscall == 3:
        msg = f"DELETE pid={pid:5d} comm={comm:<16} file='{filename}'"
        log_to(EVENTS_LOG, msg, True)
        proc_stats[pid]["deletes"].append(ts)
        if filename:
            proc_stats[pid]["files"].append((ts, filename))
        check_alerts(pid, comm)

print("🔍 Advanced monitoring started. Press Ctrl+C to stop.\n")
print(f"📁 Events: {EVENTS_LOG}")
print(f"🚨 Alerts: {ALERTS_LOG}")
print(f"⚡ Actions: {ACTIONS_LOG}")
print(f"🧾 Forensic: {FORENSIC_LOG}\n")

b["events"].open_perf_buffer(handle_event)

try:
    while True:
        b.perf_buffer_poll(timeout=200)
except KeyboardInterrupt:
    print("🛑 Stopped.")
