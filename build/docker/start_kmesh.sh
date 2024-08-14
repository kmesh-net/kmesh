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
        mkdir -p /mnt/kmesh_cgroup2
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
        echo "received SIGTERM, stopping kmesh"
        kill $pid
}

function cleanup(){
          lsmod | grep kmesh > /dev/null
          if [ $? == 0 ]; then
                  rmmod kmesh
          fi

        echo "kmesh exit"
}

trap 'stop_kmesh' SIGTERM

# wait for kmesh process to exit, cannot use wait $pid here, because the script received SIGTERM, wait will return immediately
while kill -0 $pid 2>/dev/null; do
  sleep 1
done

kmesh-daemon uninstall $@

cleanup
