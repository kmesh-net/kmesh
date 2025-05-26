#!/usr/bin/bash

source ${OET_PATH}/libs/locallibs/common_lib.sh
source ../libs/common.sh

CURRENT_PATH=$(pwd)
cd ../../../../../../
KMESH_PATH=$(pwd)

function pre_test() {
	LOG_INFO "Start environmental preparation."

	# modify Environment Variables HOME
	# mkdir rpmbuild
	cd $CURRENT_PATH/

	rm -rf rpmbuild
	mkdir rpmbuild
	cd rpmbuild
	mkdir BUILD SOURCES BUILDROOT RPMS SPECS SRPMS

	# rpmbuild files prepare
	cd $KMESH_PATH/
	KMESH_VERSION=$(grep Version: kmesh.spec | egrep -o [0-9]+.[0-9]+.[0-9]+)
	cp -r $KMESH_PATH ../kmesh_tmp
	mv ../kmesh_tmp $CURRENT_PATH/kmesh-$KMESH_VERSION
	cp kmesh.spec $CURRENT_PATH/rpmbuild/SPECS/

	cd $CURRENT_PATH
	(cd kmesh-$KMESH_VERSION/ && ./build.sh -c)
	tar zcvf kmesh-$KMESH_VERSION.tar.gz kmesh-$KMESH_VERSION/
	rm -rf kmesh-$KMESH_VERSION/
	mv kmesh-$KMESH_VERSION.tar.gz rpmbuild/SOURCES/

	LOG_INFO "End of environmental preparation!"
}

function run_test() {
	LOG_INFO "Start testing..."

	set -e
	# rpm build and install
	cd $CURRENT_PATH/rpmbuild/SPECS/
	rpmbuild --define="_topdir $CURRENT_PATH/rpmbuild/" -bb kmesh.spec
	cd $CURRENT_PATH/rpmbuild/RPMS/$(arch)/
	rpm -ivh --force kmesh-$KMESH_VERSION-1.$(arch).rpm
	rpm -ql kmesh >tmp_rpm_install.log
	grep kmesh tmp_rpm_install.log
	CHECK_RESULT $? 0 0 "rpmb install error"

	# service start and stop
	systemctl start kmesh.service
	systemctl status kmesh.service >tmp_service.log
	grep 'active (running)' tmp_service.log
	CHECK_RESULT $? 0 0 "start kmesh service error"
	systemctl stop kmesh.service

	LOG_INFO "Finish test!"
}

function post_test() {
	LOG_INFO "Start environment cleanup."

	cd $CURRENT_PATH/
	rpm -evh kmesh
	rm -rf rpmbuild

	# restore environment
	cd $KMESH_PATH
	./build.sh -i

	LOG_INFO "Finish environment cleanup!"
}

main "@"
