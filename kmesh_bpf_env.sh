#!/bin/bash

ROOT_DIR=$(dirname $(readlink -f ${BASH_SOURCE[0]}))
VERSION=$(uname -r | cut -d '.' -f 1,2)
OE_VERSION=$(uname -r | grep -o 'oe[^.]*')

if [ "$OE_VERSION" == "oe2303" ]; then
        cp $ROOT_DIR/depends/include/6.1/bpf_helper_defs_ext.h $ROOT_DIR/bpf/include/
fi
