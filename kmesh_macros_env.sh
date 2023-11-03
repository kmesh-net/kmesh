#!/bin/bash
  
VERSION=$(uname -r | cut -d '.' -f 1)
OE_VERSION=$(cat /etc/openEuler-release | awk '{print $3}')

function set_config() {
    sed -i -r -e "s/($1)([ \t]*)([0-9]+)/\1\2$2/" config/kmesh_marcos_def.h
}

# MDA_LOOPBACK_ADDR
if grep "FN(get_netns_cookie)" /usr/include/linux/bpf.h; then
	set_config MDA_LOOPBACK_ADDR 1
else
	set_config MDA_LOOPBACK_ADDR 0
fi

# MDA_NAT_ACCEL
if grep "FN(sk_original_addr)" /usr/include/linux/bpf.h; then
	set_config MDA_NAT_ACCEL 1
else
	set_config MDA_NAT_ACCEL 0
fi

# MDA_GID_UID_FILTER
if grep "FN(get_sockops_uid_gid)" /usr/include/linux/bpf.h; then
	set_config MDA_GID_UID_FILTER 1
else
	set_config MDA_GID_UID_FILTER 0
fi

# OE_23_03
if [ "$OE_VERSION" == "23.03" ]; then
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
if grep "FN(parse_header_msg)" /usr/include/linux/bpf.h; then
	set_config ENHANCED_KERNEL 1
else
	set_config ENHANCED_KERNEL 0
fi
