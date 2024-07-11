#!/bin/bash
ROOT_DIR=$(git rev-parse --show-toplevel)

go_copyright_path=$ROOT_DIR/hack/copyright/apache.txt

c_copyright_path1=$ROOT_DIR/hack/copyright/BSDandGPL1.txt
c_copyright_path2=$ROOT_DIR/hack/copyright/BSDandGPL2.txt

go_dirs="$ROOT_DIR/pkg"
c_dirs="$ROOT_DIR/bpf"

check=true

function check_go_copyright() {
    target_file=$1
    copyright_file=$go_copyright_path

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
            break
        fi
    done < "$copyright_file"

    if [ "$all_lines_present" != true ]; then
        echo "The target file does not contain all lines from the copyright file."
        echo $target_file
    fi  
}

function check_c_copyright() {
    target_file=$1
    copyright_file1=$c_copyright_path1
    copyright_file2=$c_copyright_path2

    if [ ! -f "$target_file" ]; then
        echo "Target file $target_file does not exist."
        exit 1
    fi

    if [ ! -f "$copyright_file1" ]; then
        echo "Copyright file $copyright_file1 does not exist."
        exit 1
    fi

    if [ ! -f "$copyright_file2" ]; then
        echo "Copyright file $copyright_file2 does not exist."
        exit 1
    fi

    all_lines_present1=true
    while IFS= read -r line; do
        if ! grep -qF -- "$line" "$target_file"; then
            all_lines_present1=false
            break
        fi
    done < "$copyright_file1"

    all_lines_present2=true
    while IFS= read -r line; do
        if ! grep -qF -- "$line" "$target_file"; then
            all_lines_present2=false
            break
        fi
    done < "$copyright_file2"

    if [ "$all_lines_present1" != true ] && [ "$all_lines_present2" != true ]; then
        echo "The target file does not contain all lines from the copyright file."
        echo $target_file
    fi  
}

function go_check_dir() {
    dir=$1
    find $dir -type f -name "*.go" | while read file; do
        # echo $file
        if ! echo $exclude_dirs | grep -q $(dirname $file); then
            check_go_copyright $file
        fi 
    done
}

function c_check_dir() {
    dir=$1
    find $dir -type f -name "*.c" -o -name "*.h" | while read file; do
        # echo $file
        if ! echo $exclude_dirs | grep -q $(dirname $file); then
            check_c_copyright $file
        fi 
    done
}

for dir in ${go_dirs}; do
    go_check_dir $dir
done

for dir in ${c_dirs}; do
    c_check_dir $dir
done

echo "Copyright check passed!"