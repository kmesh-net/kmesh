#!/bin/bash

ROOT_DIR=$(git rev-parse --show-toplevel)

bash $ROOT_DIR/build.sh

export PKG_CONFIG_PATH=$ROOT_DIR/mk

go test -v -vet=off -coverprofile=coverage.out ./pkg/...
