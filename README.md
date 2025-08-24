# ebpf-based-ransomware-detector

📌 Project Overview

This project aims to build a real-time ransomware detection and prevention system using eBPF (extended Berkeley Packet Filter). The system detects ransomware-like behavior at the kernel level and triggers a kill-switch to stop the malicious process before it causes significant damage. No additional hardware is required.

# Phase 1 – Setup & Research 

Configure Linux kernel with eBPF & BPF LSM enabled.

Explore BCC/libbpf tooling.

Writing simple eBPF programs to monitor file writes.

# Phase 2 – Basic Detection 

Extend eBPF programs:

Hook into vfs_write, vfs_rename, and vfs_unlink.

Send structured events (PID, command name, file path hash, bytes written, timestamp) to user space via ring buffer.

Build a user-space daemon (Go or Python) to:

Collect events from ring buffer.

Maintain counters per PID (files written, renamed, deleted).

Implement thresholds (e.g., more than 200 writes in 30s).

Add basic detection rules:

High-rate writes.

Mass renames with new extensions.


# Phase 3 – Kill-Switch Integration 

Enhance eBPF programs with BPF LSM hooks:

Use file_open, inode_rename, and inode_unlink hooks.

Check if PID exists in a deny-list map; if yes, return -EPERM (deny operation).

Extend daemon:

On detection, add offending PID to deny-list map.

Send SIGSTOP to immediately freeze the process.

Implement SIGSTOP/SIGKILL process termination.

Quarantine malicious processes using cgroups (block network + IO).

# Expected Output 

A configured Linux environment with eBPF toolchain and a minimal file-write logger.

A user-space daemon that receives kernel events, applies basic detection rules, and logs suspicious activity.

A functional kill-switch that blocks file writes and stops/quarantines simulated ransomware processes in real time.
