# tests/simulate_ransomware.py
import os
import time

# Always relative to this script's directory
base_dir = os.path.dirname(os.path.abspath(__file__))
folder = os.path.join(base_dir, "logs", "test_files")

print("📂 Target folder:", folder)
os.makedirs(folder, exist_ok=True)

for i in range(1, 161):  # create 160 files
    filepath = os.path.join(folder, f"encrypted_{i}.txt")
    with open(filepath, "wb") as f:
        f.write(os.urandom(50 * 1024))  # 50 KB
    time.sleep(0.05)

print("✅ Created 160 files in:", folder)
