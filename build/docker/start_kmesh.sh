#!/bin/sh

# docker image compile online, if not compile online, the following lines also have no effect 

lsmod | grep kmesh > /dev/null
if [ $? -ne 0 ] && [ -f kmesh.ko ]; then
	cp kmesh.ko /lib/modules/$(uname -r)
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

mount | grep "type bpf"
if [ $? -ne 0 ]; then
	mount -t bpf none /sys/fs/bpf
	if [ $? -ne 0 ]; then
		echo "mount bpf failed"
	fi
fi

kmesh-daemon $@ &
pid=$!

# pass SIGTERM to kmesh process
function stop_kmesh() {
        kill $pid
}

function cleanup(){
          lsmod | grep kmesh > /dev/null
          if [ $? == 0 ]; then
                  rmmod kmesh
          fi

          umount -t cgroup2 /mnt/kmesh_cgroup2/
          rm -rf /mnt/kmesh_cgroup2
          rm -rf /sys/fs/bpf/bpf_kmesh
}

trap 'stop_kmesh' SIGTERM
wait # wait child process exit
cleanup
