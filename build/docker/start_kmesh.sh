#!/bin/sh

lsmod | grep kmesh > /dev/null
if [ $? -ne 0 ]; then
        cp kmesh.ko /lib/modules/`uname -r`
        depmod -a
        modprobe kmesh
fi

mount | grep /mnt/kmesh_cgroup2
if [ $? -ne 0 ]; then
        mkdir /mnt/kmesh_cgroup2
        mount -t cgroup2 none /mnt/kmesh_cgroup2/
        if [ $? -ne 0 ]; then
                echo "mount cgroup2 failed"
        fi
fi

kmesh-daemon -enable-kmesh  &

function stop_kmesh() {
        pkill kmesh-daemon

        lsmod | grep kmesh > /dev/null
        if [ $? == 0 ]; then
                rmmod kmesh
        fi

        umount -t cgroup2 /mnt/kmesh_cgroup2/
        rm -rf /mnt/kmesh_cgroup2
        rm -rf /sys/fs/bpf/bpf_kmesh
}

trap 'stop_kmesh' SIGTERM

while true;
do
    sleep 60
done
