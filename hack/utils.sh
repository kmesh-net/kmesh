#!/bin/bash

function run_docker_container() {
	local container_id
	container_id=$(docker run --rm -itd --privileged=true \
		-v /usr/src:/usr/src \
		-v /usr/include/linux/bpf.h:/kmesh/config/linux-bpf.h \
		-v /etc/cni/net.d:/etc/cni/net.d \
		-v /opt/cni/bin:/opt/cni/bin \
		-v /mnt:/mnt \
		-v /sys/fs/bpf:/sys/fs/bpf \
		-v /lib/modules:/lib/modules \
		-v "$(pwd)":/kmesh \
		-v "$(go env GOCACHE)":/root/.cache/go-build \
		-v "$(go env GOMODCACHE)":/go/pkg/mod \
		-e PKG_CONFIG_PATH=/kmesh/mk \
		--name kmesh-build "ghcr.io/kmesh-net/kmesh-build:latest")

	echo "$container_id"
}

function get_arch() {
	if [ "$(arch)" == "x86_64" ]; then
		echo "x86"
	else
		echo "arm"
	fi
}

function build_kmesh() {
	local container_id=$1
	docker exec $container_id git config --global --add safe.directory /kmesh
	docker exec -e VERSION=$VERSION $container_id sh /kmesh/build.sh
	docker exec -e VERSION=$VERSION $container_id sh /kmesh/build.sh -i
	docker exec $container_id sh -c "$(declare -f copy_to_host); copy_to_host"
}

function copy_to_host() {
	mkdir -p "./out/ko"

	cp /usr/lib64/libkmesh_api_v2_c.so out/
	cp /usr/lib64/libkmesh_deserial.so out/
	cp /usr/lib64/libboundscheck.so out/
	cp oncn-mda/build/ebpf_src/CMakeFiles/sock_redirect.dir/sock_redirect.c.o out/
	cp oncn-mda/etc/oncn-mda.conf out/
	cp oncn-mda/build/ebpf_src/CMakeFiles/sock_ops.dir/sock_ops.c.o out/
	find /usr/lib64 -name 'libbpf.so*' -exec cp {} out/ \;
	find /usr/lib64 -name 'libprotobuf-c.so*' -exec cp {} out/ \;
	cp /usr/bin/kmesh-daemon out/
	cp /usr/bin/kmesh-cni out/
	cp /usr/bin/mdacore out/
	if [ -f "/lib/modules/kmesh/kmesh.ko" ]; then
		cp /lib/modules/kmesh/kmesh.ko out/ko
	fi
}

function clean_container() {
	local container_id=$1
	docker rm -f $container_id
}
