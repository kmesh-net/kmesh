#!/bin/sh
lsmod | grep kmesh >/dev/null
if [ $? == 0 ]; then
	rmmod kmesh
fi

umount -t cgroup2 /mnt/kmesh_cgroup2/
rm -rf /mnt/kmesh_cgroup2 >/dev/null
rm -rf /sys/fs/bpf/bpf_kmesh
