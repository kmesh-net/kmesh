# BPF SOCKMAP
sockmap

## Usage Tutorial
load bpf

```shell
PROG_SOCKOPS=bpf_sockops.o
PROG_REDIRECT=bpf_redirect.o

# Mount the bpf filesystem
# mount -t bpf bpf /sys/fs/bpf/
mkdir /mnt/cgroup2
mount -t cgroup2 none /mnt/cgroup2/

# Load and attach the bpf_sockops program
bpftool prog load bpf_sockops.o /sys/fs/bpf/bpf_sockops type sockops

# http://www.freeoa.net/osuport/sysadmin/linux-cgroup-detail_3446.html
bpftool cgroup attach /mnt/cgroup2/ sock_ops pinned /sys/fs/bpf/bpf_sockops

# Extract the id of the sockhash map used by the bpf_sockops program
# This map is then pinned to the bpf virtual file system
bpftool prog show pinned /sys/fs/bpf/bpf_sockops
bpftool map show id 58
bpftool map show id 57
bpftool map pin id 58 /sys/fs/bpf/skops_proxy_map
bpftool map pin id 57 /sys/fs/bpf/skops_map

# Load and attach the bpf_redir to the sock_ops_map
bpftool prog load bpf_redirect.o /sys/fs/bpf/bpf_redirect map name skops_map pinned /sys/fs/bpf/skops_map \
map name skops_proxy_map pinned /sys/fs/bpf/skops_proxy_map
bpftool prog attach pinned /sys/fs/bpf/bpf_redirect msg_verdict pinned /sys/fs/bpf/skops_map \
pinned /sys/fs/bpf/skops_proxy_map

# bpf log
cat /sys/kernel/debug/tracing/trace_pipe
```

unload bpf

```shell
# Detach and unload the bpf_redir program
bpftool prog detach pinned /sys/fs/bpf/bpf_redirect msg_verdict pinned /sys/fs/bpf/skops_map
rm -f /sys/fs/bpf/bpf_redirect

# Detach and unload the bpf_sockops program
bpftool cgroup detach /mnt/cgroup2 sock_ops pinned /sys/fs/bpf/bpf_sockops
rm -f /sys/fs/bpf/bpf_sockops

# Delete the map
rm -f /sys/fs/bpf/skops_map
rm -f /sys/fs/bpf/skops_proxy_map
```

