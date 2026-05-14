#!/bin/bash

ROOT_DIR=$(git rev-parse --show-toplevel)

PROTO_PATH=${1}
shift
PROTO_SRC=$@

# Extra proto_path so well-known types (google/protobuf/wrappers.proto, etc.)
# can be located both on the host and inside the build container. We vendor
# them under <repo_root>/third_party (= ../third_party from api/).
EXTRA_PROTO_PATH="--proto_path=../third_party"

# if protoc-c is 1.4.x
if protoc-c --version | grep -q -E "protobuf-c 1\.4\.[0-9]"; then
	protoc-c --proto_path=$PROTO_PATH $EXTRA_PROTO_PATH --c_out=. $PROTO_SRC
else
	echo "Generate proto files in docker"
	docker run --rm \
		-v $ROOT_DIR:/kmesh \
		--name kmesh-build \
		--user $(id -u):$(id -g) \
		ghcr.io/kmesh-net/kmesh-build:latest \
		sh -c "cd /kmesh/api && protoc-c --proto_path=$PROTO_PATH $EXTRA_PROTO_PATH --c_out=. $PROTO_SRC"
fi
