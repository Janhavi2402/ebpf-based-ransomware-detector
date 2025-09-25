#!/usr/bin/env python3
# tests/simulate_trigger.py
"""
Run while loader.py is running (in another terminal with sudo).
This script writes a number of small files quickly then deletes them,
to trigger the detection thresholds.
"""
import os
import time
from pathlib import Path

TARGET = Path.cwd() / "logs" / "test_files_trigger"
TARGET.mkdir(parents=True, exist_ok=True)
print("Target folder:", TARGET)

N = 12
SLEEP = 0.03
SIZE = 8 * 1024  # 8 KB

for i in range(N):
    p = TARGET / f"sim_{i:03d}.dat"
    with open(p, "wb") as f:
        f.write(os.urandom(SIZE))
    time.sleep(SLEEP)

time.sleep(0.5)

# delete them fast
for p in sorted(TARGET.glob("sim_*.dat")):
    try:
        p.unlink()
    except:
        pass
    time.sleep(0.02)

print("Simulation complete.")
