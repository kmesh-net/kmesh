#!/bin/bash

KMESH_DIR=$(dirname $(pwd))

docker buildx build --platform linux/amd64 -t kmesh:build -f docker/kmesh-compiler.dockerfile $KMESH_DIR
