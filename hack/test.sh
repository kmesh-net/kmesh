#!/bin/sh

target_file="/home/lzcworkspace/library/src/kmesh.net/kmesh/pkg/status/status_server.go"       # 目标文件路径
copyright_file="./hack/copyright/apache.txt"  # 版权声明文件路径

if [ ! -f "$target_file" ]; then
    echo "Target file $target_file does not exist."
    exit 1
fi

if [ ! -f "$copyright_file" ]; then
    echo "Copyright file $copyright_file does not exist."
    exit 1
fi

all_lines_present=true
while IFS= read -r line; do
    if ! grep -qF -- "$line" "$target_file"; then
        all_lines_present=false
        echo "Line not found: $line"
        break
    fi
done < "$copyright_file"

if [ "$all_lines_present" = true ]; then
    echo "The target file contains all lines from the copyright file."
else
    echo "The target file does not contain all lines from the copyright file."
fi