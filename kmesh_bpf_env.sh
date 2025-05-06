#!/bin/bash

ROOT_DIR=$(dirname $(readlink -f ${BASH_SOURCE[0]}))
VERSION=$(uname -r | cut -d '.' -f 1,2)
OE_VERSION=$(uname -r | grep -o 'oe[^.]*')

# new bpf helper functions name in the kernel, if there are any new functions
# added in the future, please add them to the list.
helper_name=(
	km_header_strnstr
	km_header_strncmp
	parse_header_msg
)

base_line=$(grep -nr "FN(unspec)" $KERNEL_HEADER_LINUX_BPF | awk -F ":" {'print $1'})
for name in ${helper_name[@]}; do
	current_line=$(grep -nr "FN($name)" $KERNEL_HEADER_LINUX_BPF | awk -F ":" {'print $1'})
	if [ -n "$current_line" ]; then
		helper_id=$(expr $current_line - $base_line)
		sed -Ei "/${name}_num/s/([0-9]+)[^0-9]*$/$helper_id/" $ROOT_DIR/bpf/include/bpf_helper_defs_ext.h
	fi
done
