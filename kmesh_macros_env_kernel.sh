#!/bin/bash
  
VERSION=$(uname -r | cut -d '.' -f 1)
KERNEL_VERSION=$(uname -r | cut -d '-' -f 1)
KERNEL_HEADER_LINUX_BPF=/usr/include/linux/bpf.h

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

# KERNEL_KFUNC
if [ "$VERSION" -ge 6 ]; then
	set_config ENHANCED_KERNEL 1
	set_config KERNEL_KFUNC 1
else
	set_config KERNEL_KFUNC 0
fi