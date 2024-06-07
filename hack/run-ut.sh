#!/bin/bash

ROOT_DIR=$PWD

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib:$ROOT_DIR/api/v2-c:$ROOT_DIR/bpf/deserialization_to_bpf_map
export PKG_CONFIG_PATH=$ROOT_DIR/mk
go test -v -vet=off -coverprofile=coverage.out ./pkg/...