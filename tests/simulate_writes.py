import os, time

folder = "../logs/test_files/"
os.makedirs(folder, exist_ok=True)

for i in range(1, 21):
    with open(f"{folder}file_{i}.txt", "w") as f:
        f.write(f"Test file {i}\n")
    time.sleep(0.1)

print("Simulation done.")
