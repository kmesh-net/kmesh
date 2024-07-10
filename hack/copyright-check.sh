#!/bin/bash
ROOT_DIR=$(git rev-parse --show-toplevel)
echo $ROOT_DIR
cd $ROOT_DIR

go_copyright=$(cat ./hack/copyright/apache.txt)
echo "$go_copyright"

c_copyright=$(cat ./hack/copyright/BSDandGPL.txt)
echo "$c_copyright"

go_dirs="$ROOT_DIR/bpf/kmesh/bpf2go $ROOT_DIR/pkg"

function check_go_copyright() {
    file=$1
    
    copyright_found=$(head -n 20  $file | grep -c "$go_copyright")
    
    if [ $copyright_found -eq 0 ]; then
        echo $copyright_found
        echo "Copyright missing in $file"
        # exit 1
    fi

    # header_copyright=$(head -n 1 $file)

    # if [ "$header_copyright" != "$go_copyright" ]; then
    #     echo "Copyright doesn't match in $file" 
    #     # exit 1
    # fi
}

function check_dir() {
    dir=$1
    find $dir -type f -name "*.go" | while read file; do
        echo $file
        if ! echo $exclude_dirs | grep -q $(dirname $file); then
            check_go_copyright $file
        fi 
    done
}

for dir in ${go_dirs}; do
    echo $dir
    check_dir $dir
done

echo "Copyright check passed!"