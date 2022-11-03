#!/usr/bin/bash

IPADDR=$1
PASSWD=$2
USER=${3-root}
PORT=${4-22}

CURRENT_PATH=$(pwd)

function code_compile() {
    local ARCH=$(arch)
    if [ "$ARCH" == "x86_64" ]; then
        export EXTRA_GOFLAGS="-gcflags=\"-N -l\""
        export EXTRA_CFLAGS="-O0 -g"
        export EXTRA_CDEFINE="-D__x86_64__"
    fi

    cd $CURRENT_PATH
    cd ../

    local tmp_path=$(pwd)
    cp $tmp_path/vendor/google.golang.org/protobuf/cmd/protoc-gen-go/protoc-gen-go /usr/bin/
    make clean
    make
    make install

    cd kernel/ko_src
    make
    mkdir -p /lib/modules/kmesh
    cp ../ko/kmesh.ko /lib/modules/kmesh/

    cd $CURRENT_PATH
}

function packages_install() {
    yum install -y make golang clang libbpf-devel llvm libboundscheck protobuf protobuf-c protobuf-c-devel
}

function test() {
    rm -rf mugen-master
    unzip testframe/mugen-master.zip > /dev/null
    cp -rf testcases/kmesh mugen-master/testcases/smoke-test/
    cp -rf testcases/kmesh.json mugen-master/suite2cases/

    cd mugen-master
    bash dep_install.sh
    bash mugen.sh -c --ip $IPADDR --password $PASSWD --user $USER --port $PORT

    bash mugen.sh -f kmesh -x

    if [ -d results/kmesh ]; then
        if [ -d results/kmesh/succeed ]; then
            ls results/kmesh/succeed/ > succeed.log
            echo "The following test cases run success"
            echo "--------------------------------------->"
            cat succeed.log
            echo "<---------------------------------------"
        fi

        if [ -d results/kmesh/failed ]; then
            ls results/kmesh/failed/ > failed.log
            echo "The following test cases run failed"
            echo "--------------------------------------->"
            cat failed.log
            echo "<---------------------------------------"
        fi
            
        echo "****************************************"
        echo "NOTICE:The test cases execution log is recorded in mugen-master/logs/kmesh/"
        echo "****************************************"
    else
        echo "ERROR:test cases not run!"
    fi
}

packages_install
code_compile
test
