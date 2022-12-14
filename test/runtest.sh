#!/usr/bin/bash

IPADDR=$1
PASSWD=$2
TESTCASE=${3-ALL}
USER=${4-root}
PORT=${5-22}

CURRENT_PATH=$(pwd)

function code_compile() {
    cd $CURRENT_PATH/../
    ./build.sh -u
    ./build.sh -b
    ./build.sh -i
}

function env_reset() {
    cd $CURRENT_PATH/../
    ./build.sh -u
}

function packages_install() {
    yum install -y make golang clang libbpf-devel llvm libboundscheck protobuf protobuf-c protobuf-c-devel bpftool rpm-build rpmdevtools
}

function runtest() {
    cd $CURRENT_PATH

    rm -rf mugen-master
    unzip testframe/mugen-master.zip > /dev/null
    cp -rf testcases/kmesh mugen-master/testcases/smoke-test/
    cp -rf testcases/kmesh.json mugen-master/suite2cases/

    cd mugen-master
    bash dep_install.sh
    bash mugen.sh -c --ip $IPADDR --password $PASSWD --user $USER --port $PORT

    if [ $TESTCASE == 'ALL' ]; then
	    bash mugen.sh -f kmesh -x
    else
	    bash mugen.sh -f kmesh -r $TESTCASE -x
    fi

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
runtest
env_reset
