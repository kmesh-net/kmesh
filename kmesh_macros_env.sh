#!/bin/bash
  
VERSION=$(uname -r | cut -d '.' -f 1)
KERNEL_VERSION=$(uname -r | cut -d '-' -f 1)

function set_config() {
    sed -i -r -e "s/($1)([ \t]*)([0-9]+)/\1\2$2/" config/kmesh_marcos_def.h
}

# MDA_LOOPBACK_ADDR
if grep -q "FN(get_netns_cookie)" $KERNEL_HEADER_LINUX_BPF; then
	set_config MDA_LOOPBACK_ADDR 1
else
	set_config MDA_LOOPBACK_ADDR 0
fi

# MDA_NAT_ACCEL
if grep -q "FN(sk_original_addr)" $KERNEL_HEADER_LINUX_BPF; then
	set_config MDA_NAT_ACCEL 1
else
	set_config MDA_NAT_ACCEL 0
fi

# MDA_GID_UID_FILTER
if grep -q "FN(get_sockops_uid_gid)" $KERNEL_HEADER_LINUX_BPF; then
	set_config MDA_GID_UID_FILTER 1
else
	set_config MDA_GID_UID_FILTER 0
fi

# OE_23_03
if (uname -r | grep oe2303); then
	set_config OE_23_03 1
else
	set_config OE_23_03 0
fi

# ITER_TYPE_IS_UBUF
if [ "$VERSION" -ge 6 ]; then
	set_config ITER_TYPE_IS_UBUF 1
else
	set_config ITER_TYPE_IS_UBUF 0
fi

# ENHANCED_KERNEL
if grep -q "FN(parse_header_msg)" $KERNEL_HEADER_LINUX_BPF; then
	set_config ENHANCED_KERNEL 1
else
	set_config ENHANCED_KERNEL 0
fi

# Determine libbpf version
if command -v apt > /dev/null; then
	LIBBPF_VERSION=$(ls /usr/lib/x86_64-linux-gnu | grep -P 'libbpf\.so\.\d+\.\d+\.\d+$' | sed -n -e 's/^.*libbpf.so.\(.*\)$/\1/p')
else
	LIBBPF_VERSION=$(ls /usr/lib64 | grep -P 'libbpf\.so\.\d+\.\d+\.\d+$' | sed -n -e 's/^.*libbpf.so.\(.*\)$/\1/p')
fi

if [[ "$LIBBPF_VERSION" < "0.6.0" ]]; then
	set_config LIBBPF_HIGHER_0_6_0_VERSION 0
else
	set_config LIBBPF_HIGHER_0_6_0_VERSION 1
fi

if [[ "$KERNEL_VERSION" < "5.13.0" ]]; then
	set_config KERNEL_VERSION_HIGHER_5_13_0 0
else
	set_config KERNEL_VERSION_HIGHER_5_13_0 1
fi