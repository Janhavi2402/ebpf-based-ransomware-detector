# src/detector.py
import time, re, os
from collections import defaultdict, deque

log_file = os.path.join(os.path.dirname(_file_), "..", "logs", "events.log")

# thresholds (tweak as needed)
MAX_WRITES = 50
MAX_DELETES = 10
TIME_WINDOW = 5  # seconds

history = defaultdict(lambda: deque())

def detect():
    with open(log_file, "r") as f:
        f.seek(0, os.SEEK_END)  # start at end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue

            ts_match = re.match(r"\[(.*?)\]", line)
            if not ts_match:
                continue

            ts = time.time()
            pid_match = re.search(r"pid=(\d+)", line)
            pid = int(pid_match.group(1)) if pid_match else -1

            # classify event
            if "WRITE" in line:
                history[("write", pid)].append(ts)
            elif "UNLINK" in line:
                history[("unlink", pid)].append(ts)

            # clean up old entries
            for k in list(history.keys()):
                while history[k] and ts - history[k][0] > TIME_WINDOW:
                    history[k].popleft()

            # detection rules
            if len(history[("write", pid)]) > MAX_WRITES:
                print(f"[ALERT] Rapid file writes by PID {pid}")
            if len(history[("unlink", pid)]) > MAX_DELETES:
                print(f"[ALERT] Rapid file deletions by PID {pid}")

if _name_ == "_main_":
    print("🚨 Suspicious Activity Detector running...")
    detect()