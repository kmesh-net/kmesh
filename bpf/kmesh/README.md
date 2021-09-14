# BPF KMESH
kmesh

## Usage Tutorial
load bpf connect4

```shell
# Mount the bpf filesystem
# mount -t bpf bpf /sys/fs/bpf/
mkdir /mnt/cgroup2
mount -t cgroup2 none /mnt/cgroup2/

# Load object file into kernel
bpftool prog load bpf_sock.o /sys/fs/bpf/bpf_sock_connect4 type cgroup/connect4

# Attach to cgroup
bpftool cgroup attach /mnt/cgroup2/ connect4 pinned /sys/fs/bpf/bpf_sock_connect4
bpftool cgroup show  /mnt/cgroup2

# bpf log
cat /sys/kernel/debug/tracing/trace_pipe
```

unload bpf connect4

```shell
# bpftool cgroup detach <cgroup root> <hook> id <id>
bpftool cgroup detach /mnt/cgroup2 connect4 pinned /sys/fs/bpf/bpf_sock_connect4
rm -f /sys/fs/bpf/bpf_sock_connect4
```

