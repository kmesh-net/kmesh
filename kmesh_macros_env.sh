#!/bin/bash
  
VERSION=$(uname -r | cut -d '.' -f 1,2)
OE_VERSION=$(uname -r | grep -o 'oe[^.]*')

function set_config() {
    sed -i -r -e "s/($1)([ \t]*)([0-9]+)/\1\2$2/" config/kmesh_marcos_def.h
}

function set_config_oe2303() {
    set_config MDA_LOOPBACK_ADDR 1
    set_config MDA_NAT_ACCEL 0
    set_config MDA_GID_UID_FILTER 0
    set_config MDA_PORT_OFFSET 0
    set_config OE_23_03 1
    set_config ITER_TYPE_IS_UBUF 1
    set_config ISENHANCED_KERNEL 1
}

function set_config_all_disabled() {
    set_config MDA_LOOPBACK_ADDR 0
    set_config MDA_NAT_ACCEL 0
    set_config MDA_GID_UID_FILTER 0
    set_config MDA_PORT_OFFSET 1
    set_config OE_23_03 0
    set_config ITER_TYPE_IS_UBUF 0
    set_config ISENHANCED_KERNEL 0
}

function set_kmesh_env_config() {

   # openEuler 2303
    if [ "$OE_VERSION" == "oe2303" ]; then
            set_config_oe2303
    else
            set_config_all_disabled
    fi
}
set_kmesh_env_config
