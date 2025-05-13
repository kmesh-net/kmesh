#!/bin/sh
lsmod | grep kmesh >/dev/null
if [ $? == 0 ]; then
	rmmod kmesh
	depmod -a
	modprobe kmesh
else
	depmod -a
	modprobe kmesh
fi

mount | grep /mnt/kmesh_cgroup2
if [ $? -ne 0 ]; then
	mkdir /mnt/kmesh_cgroup2
	mount -t cgroup2 none /mnt/kmesh_cgroup2/
fi
