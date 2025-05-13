#!/bin/bash
ROOT_DIR=$(dirname $(readlink -f ${BASH_SOURCE[0]}))
source ./kmesh_compile_env_pre.sh

function install() {
	mkdir -p /etc/kmesh
	chmod 700 /etc/kmesh

	cp $ROOT_DIR/build/kmesh-start-pre.sh /usr/bin
	chmod 500 /usr/bin/kmesh-start-pre.sh
	cp $ROOT_DIR/build/kmesh-stop-post.sh /usr/bin
	chmod 500 /usr/bin/kmesh-stop-post.sh

	mkdir -p /etc/oncn-mda
	chmod 700 /etc/oncn-mda
	cp $ROOT_DIR/oncn-mda/etc/oncn-mda.conf /etc/oncn-mda/
	chmod 600 /etc/oncn-mda/oncn-mda.conf
}

function uninstall() {
	rm -rf /etc/kmesh
	rm -rf /usr/bin/kmesh-start-pre.sh
	rm -rf /usr/bin/kmesh-stop-post.sh
	rm -rf /etc/oncn-mda
	rm -rf /usr/share/oncn-mda
}

function clean() {
	rm -rf /etc/kmesh
	rm -rf /usr/bin/kmesh-start-pre.sh
	rm -rf /usr/bin/kmesh-stop-post.sh
}

set_enhanced_kernel_env

if [ "$1" == "-h" -o "$1" == "--help" ]; then
	echo build.sh -h/--help : Help.
	echo build.sh -b/--build: Build Kmesh.
	echo build.sh -i/--install: Install Kmesh.
	echo build.sh -c/--clean: Clean the built binary.
	echo build.sh -u/--uninstall: Uninstall Kmesh.
	exit
fi

if [ -z "$1" -o "$1" == "-b" -o "$1" == "--build" ]; then
	prepare
	make
	exit
fi

if [ "$1" == "-i" -o "$1" == "--install" ]; then
	make install
	install
	exit
fi

if [ "$1" == "-u" -o "$1" == "--uninstall" ]; then
	make uninstall
	uninstall
	exit
fi

if [ "$1" == "-c" -o "$1" == "--clean" ]; then
	make clean
	clean
	exit
fi
