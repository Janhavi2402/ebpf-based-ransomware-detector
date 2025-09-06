// src/monitor_ebpf.c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>   // TASK_COMM_LEN

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[256];  // for openat/unlinkat; empty for write
    int syscall;         // 1=openat, 2=write, 3=unlinkat
    int fd;              // for write()
    u64 count;           // bytes for write()
};

BPF_PERF_OUTPUT(events);

// ---------- openat ----------
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct data_t data = {};
    data.syscall = 1;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // args->filename is const char __user*
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);

    data.fd = -1;
    data.count = 0;

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// ---------- write ----------
TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    struct data_t data = {};
    data.syscall = 2;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // no filename available here – capture fd + count
    data.filename[0] = '\0';
    data.fd = args->fd;
    data.count = args->count;

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// ---------- unlinkat (delete) ----------
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    struct data_t data = {};
    data.syscall = 3;
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // args->pathname is const char __user*
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->pathname);

    data.fd = -1;
    data.count = 0;

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
