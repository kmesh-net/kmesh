#!/bin/bash
set -e

ROOT_DIR=$(git rev-parse --show-toplevel)
OUT_DIR=${ROOT_DIR}/test/bpf_ut

mkdir -p "${OUT_DIR}"

echo "[+] Building all bpf_ut test object files..."

COMMON_FLAGS="-g -O2 -target bpf -std=gnu99 -Wall -Wextra -fPIC \
-D__NR_CPUS__=$(nproc) -D__TARGET_ARCH_x86_64 -D__x86_64__ -D_GNU_SOURCE -DKERNEL_VERSION_HIGHER_5_13_0=1"

INCLUDES="\
-isystem /usr/include \
-I/usr/local/include \
-I./include \
-I${ROOT_DIR}/bpf/include \
-I${ROOT_DIR}/bpf/kmesh/ \
-I${ROOT_DIR}/bpf/kmesh/probes \
-I${ROOT_DIR}/bpf/kmesh/workload/include \
-I${ROOT_DIR}/bpf/kmesh/general/include \
-I${ROOT_DIR}/bpf/kmesh/general \
-I${ROOT_DIR}/api/v2-c"

#workload_sendmsg_test.c
clang $COMMON_FLAGS $INCLUDES -DKMESH_UNIT_TEST -c ${OUT_DIR}/workload_sendmsg_test.c -o ${OUT_DIR}/workload_sendmsg_test.o

#workload_sockops_test.c
clang $COMMON_FLAGS $INCLUDES -I${ROOT_DIR}/bpf/kmesh/probes -c ${OUT_DIR}/workload_sockops_test.c -o ${OUT_DIR}/workload_sockops_test.o

#workload_cgroup_skb_test.c
clang $COMMON_FLAGS $INCLUDES -I${ROOT_DIR}/bpf/kmesh/probes -c ${OUT_DIR}/workload_cgroup_skb_test.c -o ${OUT_DIR}/workload_cgroup_skb_test.o

#tc_mark_encrypt_test.c and tc_mark_decrypt_test.c
TC_FLAGS="-I${ROOT_DIR}/bpf/kmesh/general/include -I${ROOT_DIR}/bpf/kmesh/general"

clang $COMMON_FLAGS $INCLUDES $TC_FLAGS -c ${OUT_DIR}/tc_mark_encrypt_test.c -o ${OUT_DIR}/tc_mark_encrypt_test.o
clang $COMMON_FLAGS $INCLUDES $TC_FLAGS -c ${OUT_DIR}/tc_mark_decrypt_test.c -o ${OUT_DIR}/tc_mark_decrypt_test.o

echo "[✓] Done."
