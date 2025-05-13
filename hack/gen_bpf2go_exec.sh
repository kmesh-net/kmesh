#!/bin/bash

ROOT_DIR=$(git rev-parse --show-toplevel)
. $ROOT_DIR/hack/utils.sh
. $ROOT_DIR/kmesh_compile_env_pre.sh

kmesh_exec() {
	set_enhanced_kernel_env
	prepare
	go generate bpf/kmesh/bpf2go/bpf2go.go
}
kmesh_exec
