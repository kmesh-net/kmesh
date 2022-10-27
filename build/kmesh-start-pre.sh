#!/bin/sh
lsmod | grep kmesh > /dev/null
if [ $? == 0 ]; then
	rmmod kmesh
	depmod -a
	modprobe kmesh
else
	depmod -a
	modprobe kmesh
fi

mkdir /mnt/cgroup2
mount -t cgroup2 none /mnt/cgroup2/
