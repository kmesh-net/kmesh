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

function install_protoc () {
    desired_version="3.17.3"
    # Check if protoc is installed
    if command -v protoc >/dev/null 2>&1; then
        # Get the installed version
        installed_version=$(protoc --version | awk '{print $2}')
        echo "Installed protoc version: $installed_version"
        # Compare the installed version with the desired version
        if [[ "$installed_version" == "$desired_version" ]]; then
            echo "Installed protoc version matches the desired version."
        else
            echo "Installed protoc version does not match the desired version."
            # install protoc
            wget https://github.com/protocolbuffers/protobuf/releases/download/v3.17.3/protoc-3.17.3-linux-x86_64.zip
            unzip protoc-3.17.3-linux-x86_64.zip -d protoc-3.17.3
            sudo mv protoc-3.17.3/bin/protoc /usr/local/bin/
            rm -rf protoc-3.17.3-linux-x86_64.zip protoc-3.17.3
        fi
    else
        echo "protoc is not installed"
        # install protoc
        wget https://github.com/protocolbuffers/protobuf/releases/download/v3.17.3/protoc-3.17.3-linux-x86_64.zip
        unzip protoc-3.17.3-linux-x86_64.zip -d protoc-3.17.3
        sudo mv protoc-3.17.3/bin/protoc /usr/local/bin/
        rm -rf protoc-3.17.3-linux-x86_64.zip protoc-3.17.3
    fi

    tools=()

    if command -v protoc > /dev/null; then
        echo "protoc already installed"
    else
        tools+=(protobuf-compiler)
    fi

    if command -v protoc-c > /dev/null; then
        echo "protoc-c already installed"
    else
        tools+=(protobuf-c-compiler)
    fi

    if [ ${#tools[@]} -gt 0 ]; then
        sudo apt-get update
        for element in "${tools[@]}"
        do
            install_tool $element
        done
    fi


    if command -v protoc-gen-go > /dev/null; then
        echo "protoc-gen-go already installed"
    else
        go install google.golang.org/protobuf/cmd/protoc-gen-go
    fi
}

install_protoc
