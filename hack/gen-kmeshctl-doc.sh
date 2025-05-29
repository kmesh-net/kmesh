#!/bin/bash

ROOT_DIR=$(git rev-parse --show-toplevel)

cd "$ROOT_DIR/ctl/doc"
go run -tags docgen gen.go
