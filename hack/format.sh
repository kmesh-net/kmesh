#!/bin/bash


function install_tool () {
    tool=${1}
    if command -v apt > /dev/null; then
	    sudo apt-get install -y $tool
    elif command -v yum > /dev/null; then
	    # yum install
	    sudo yum install -y $tool
    fi
}

function install_clang_format () {
    if command -v clang-format > /dev/null; then
        echo "clang-format already installed"
    else
        install_tool clang-format
    fi
}

install_clang_format

find ./ -path "./api/v2-c" -prune -o -name "*.[ch]" -exec clang-format -i {} \;