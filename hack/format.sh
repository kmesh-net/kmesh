#!/bin/bash

function install_tool() {
	tool=${1}
	if command -v apt >/dev/null; then
		sudo apt-get install -y $tool
	elif command -v yum >/dev/null; then
		# yum install
		sudo yum install -y $tool
	fi
}

function install_clang_format() {
	if command -v clang-format >/dev/null; then
		echo "clang-format already installed"
	else
		install_tool clang-format
	fi
}

function install_shfmt() {
	if command -v shfmt >/dev/null; then
		echo "shfmt already installed"
	else
		install_tool shfmt
	fi
}

install_clang_format

install_shfmt

find ./ -name "*.[ch]" | grep -v pb-c | xargs clang-format -i

gofmt -w -s ../

shfmt -w -s ../
