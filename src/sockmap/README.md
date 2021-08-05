# BPF SOCKMAP
sockmap

## Usage Tutorial
load bpf

```shell
PROG_SOCKOPS=sockops_ip4.bpf.o
PROG_REDIRECT=redirect_tcp.bpf.o

# Mount the bpf filesystem
# mount -t bpf bpf /sys/fs/bpf/
mkdir /mnt/cgroup2
mount -t cgroup2 none /mnt/cgroup2/

# Load and attach the bpf_sockops program
bpftool prog load sockops_ip4.bpf.o /sys/fs/bpf/sockops_ip4 type sockops

# http://www.freeoa.net/osuport/sysadmin/linux-cgroup-detail_3446.html
bpftool cgroup attach /mnt/cgroup2/ sock_ops pinned /sys/fs/bpf/sockops_ip4

# Extract the id of the sockhash map used by the bpf_sockops program
# This map is then pinned to the bpf virtual file system
bpftool prog show pinned /sys/fs/bpf/sockops_ip4
bpftool map show id 58
bpftool map show id 57
bpftool map pin id 58 /sys/fs/bpf/skops_proxy_map
bpftool map pin id 57 /sys/fs/bpf/skops_map

# Load and attach the bpf_redir to the sock_ops_map
bpftool prog load redirect_tcp.bpf.o /sys/fs/bpf/redirect_tcp map name skops_map pinned /sys/fs/bpf/skops_map \
map name skops_proxy_map pinned /sys/fs/bpf/skops_proxy_map
bpftool prog attach pinned /sys/fs/bpf/redirect_tcp msg_verdict pinned /sys/fs/bpf/skops_map \
pinned /sys/fs/bpf/skops_proxy_map

[root@vm-x86-10822 build]# bpftool prog
140: sock_ops  name bpf_sockmap  tag be81b63eac0518fa  gpl
	loaded_at 2021-08-05T16:26:41+0800  uid 0
	xlated 2544B  jited 1383B  memlock 4096B  map_ids 58,57
	btf_id 197
144: sk_msg  name bpf_tcpip_bypas  tag f7a010ff6a472bbb  gpl
	loaded_at 2021-08-05T16:27:44+0800  uid 0
	xlated 600B  jited 341B  memlock 4096B  map_ids 58,57
	btf_id 202

# bpf log
cat /sys/kernel/debug/tracing/trace_pipe
```

unload bpf

```shell
# Detach and unload the bpf_redir program
bpftool prog detach pinned /sys/fs/bpf/redirect_tcp msg_verdict pinned /sys/fs/bpf/skops_map
rm -f /sys/fs/bpf/redirect_tcp

# Detach and unload the bpf_sockops program
bpftool cgroup detach /mnt/cgroup2 sock_ops pinned /sys/fs/bpf/sockops_ip4
rm -f /sys/fs/bpf/sockops_ip4

# Delete the map
rm -f /sys/fs/bpf/skops_map
rm -f /sys/fs/bpf/skops_proxy_map
```

