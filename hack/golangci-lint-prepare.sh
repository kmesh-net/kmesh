#!/bin/bash
ROOT_DIR=$(git rev-parse --show-toplevel)

TARGET_DIR="$ROOT_DIR/bpf/kmesh/bpf2go/kernelnative/enhanced"

FILES=(
	"kmeshsockops_bpfel.o"
	"kmeshsockops_bpfeb.o"
	"kmeshsockopscompat_bpfeb.o"
	"kmeshsockopscompat_bpfel.o"
)

mkdir -p "$TARGET_DIR"

for FILE in "${FILES[@]}"; do
	touch "$TARGET_DIR/$FILE"
done

echo "All files have been created in $TARGET_DIR."
