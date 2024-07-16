#!/bin/bash

ROOT_DIR=$(git rev-parse --show-toplevel)

. $ROOT_DIR/hack/utils.sh

PROTO_PATH=${1}; shift
PROTO_SRC=$@

arch=$(get_arch)

# if protoc-c is 1.4.x
if protoc-c --version | grep -q -E "protobuf-c 1\.4\.[0-9]"; then
    protoc-c --proto_path=$PROTO_PATH --c_out=. $PROTO_SRC
else
    echo "Generate proto files in docker"
    docker run --rm \
        -v $ROOT_DIR:/kmesh \
        --name kmesh-build \
        ghcr.io/kmesh-net/kmesh-build-${arch}:latest \
        sh -c "cd /kmesh/api && protoc-c --proto_path=$PROTO_PATH --c_out=. $PROTO_SRC"
fi

