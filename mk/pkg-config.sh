#!/bin/bash
ROOT_DIR=$(dirname $(readlink -f ${BASH_SOURCE[0]}))
ROOT_DIR=$(dirname ${ROOT_DIR})

# for pkg-config to use mk/*.pc
export PKG_CONFIG_PATH=/usr/share/pkgconfig
PKG_CONFIG_FILE="api-v1-c.pc api-v2-c.pc bpf.pc"

arg_file=$0
arg_input=$1

function fc_help()
{
	echo "${arg_file} { set | unset }"
}

function fc_set_pc()
{
	PKG_FILE_PATH=

	# add escape character to path
	for i in `seq ${#ROOT_DIR}`;
	do
		c=${ROOT_DIR:$i-1:1}

		if [ "$c" == "/" ]
		then
			PKG_FILE_PATH+='\'
		fi
		PKG_FILE_PATH+=$c
	done

	find ./ -name "*.pc" | xargs sed -i "s/^prefix=.*/prefix=${PKG_FILE_PATH}/g"

	cd ${ROOT_DIR}/mk
	cp -f ${PKG_CONFIG_FILE} ${PKG_CONFIG_PATH}
	cd -
}

function fc_unset_pc()
{
	find ./ -name "*.pc" | xargs sed -i "s/^prefix=.*/prefix=/g"

	cd ${PKG_CONFIG_PATH}
	rm -f ${PKG_CONFIG_FILE}
	cd -
}

if [ "$arg_input" == "set" ]
then
	fc_set_pc
elif [ "$arg_input" == "unset" ]
then
	fc_unset_pc
else
	fc_help
fi
