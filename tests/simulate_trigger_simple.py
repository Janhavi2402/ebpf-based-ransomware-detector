#!/usr/bin/env python3
# tests/simulate_trigger_simple.py
import os, time
from pathlib import Path

TARGET_DIR = Path.cwd() / "logs" / "test_files_trigger_simple"
NUM_FILES = 1
WRITE_SIZE = 1024
PAUSE_BETWEEN_WRITES = 0.05
PAUSE_BEFORE_DELETE = 0.3
PAUSE_BETWEEN_DELETES = 0.02

def main():
    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    print("Target folder:", TARGET_DIR)

    # cleanup previous sim files
    for old in sorted(TARGET_DIR.glob("sim_file_*.bin")):
        try:
            old.unlink()
        except Exception:
            pass

    created = []
    print(f"Creating {NUM_FILES} files (~{WRITE_SIZE} bytes each)...")
    for i in range(1, NUM_FILES + 1):
        p = TARGET_DIR / f"sim_file_{i:04d}.bin"
        with open(p, "wb") as f:
            f.write(os.urandom(WRITE_SIZE))
        created.append(p)
        print("  wrote:", p)
        time.sleep(PAUSE_BETWEEN_WRITES)

    print(f"Waiting {PAUSE_BEFORE_DELETE}s then deleting files...")
    time.sleep(PAUSE_BEFORE_DELETE)

    for p in created:
        try:
            p.unlink()
            print("  deleted:", p)
        except Exception as e:
            print("  delete error:", e)
        time.sleep(PAUSE_BETWEEN_DELETES)

    print("Simulation finished. Check logs/events.log, logs/alerts.log, logs/actions.log")

if __name__ == "__main__":
    main()
