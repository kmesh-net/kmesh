#!/bin/bash

# Exit on error
set -e

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
	echo "Please run as root"
	exit 1
fi

# Set memory limits
ulimit -l unlimited

# Create necessary directories
mkdir -p /sys/fs/bpf/prog
mkdir -p /sys/fs/bpf/map
mkdir -p /tmp/coverage

# Define paths
ELF_FILE="xdp.bpf.o"
PROG_PIN_DIR="/sys/fs/bpf/prog"
MAP_PIN_DIR="/sys/fs/bpf/map"
BLOCK_LIST="/tmp/coverage/block.list"
COVERAGE_OUTPUT="/tmp/coverage/coverage.html"

# Clean up old pins
rm -rf ${PROG_PIN_DIR}/* ${MAP_PIN_DIR}/* || true

# Clean and rebuild
echo "Cleaning and rebuilding..."
make clean
make

# 1. Load and instrument BPF program
echo "Loading and instrumenting BPF program..."
coverbee load \
	--elf=${ELF_FILE} \
	--prog-pin-dir=${PROG_PIN_DIR} \
	--map-pin-dir=${MAP_PIN_DIR} \
	--block-list=${BLOCK_LIST} \
	--log=/tmp/coverage/coverbee.log

# 2. Run tests
echo "Running tests..."
./xdp_test

# 3. Collect coverage data
echo "Collecting coverage data..."
coverbee cover \
	--map-pin-dir=${MAP_PIN_DIR} \
	--block-list=${BLOCK_LIST} \
	--output=${COVERAGE_OUTPUT} \
	--format=html

# 4. Cleanup
echo "Cleaning up..."
rm -rf ${PROG_PIN_DIR}/*
rm -rf ${MAP_PIN_DIR}/*

echo "Coverage report generated at: ${COVERAGE_OUTPUT}"
