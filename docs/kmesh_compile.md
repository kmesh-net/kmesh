# Compiling and Building Kmesh

## prerequisite

The Kmesh needs to be compiled and built in the Linux environment with the Kmesh kernel enhancement feature. Currently, [openEuler 23.03](https://repo.openeuler.org/openEuler-23.03/everything/x86_64/) is natively supported.

## build

### build from source

- Code download

  ```sh
  [root@ ~]# git clone https://github.com/kmesh-net/kmesh.git
  ```

- Code compilation

  ```sh
  [root@ ~]# cd kmesh/
  [root@ ~]# ./build.sh -b
  ```

- Program installation

  ```sh
  # The installation script displays the locations of all installation files for Kmesh
  [root@ ~]# ./build.sh -i
  ```

- Compilation cleanup

  ```sh
  [root@ ~]# ./build.sh -c
  ```

- Program uninstallation

  ```sh
  [root@ ~]# ./build.sh -u
  ```

### RPM compilation and installation

- prerequisite

  ```sh
[root@dev tmp]# yum install -y rpm-build rpmdevtools
  ```
  
- source code

  ```sh
  [root@dev tmp]# git clone https://github.com/kmesh-net/kmesh.git
  ```

- create build environment

  ```sh
  [root@dev Kmesh]# rpmdev-setuptree
  ```
  
- the code package and spec are stored in the build environment

  ```sh
  # The code package is stored in /root/rpmbuild/SOURCE
  # Note: The name of the compressed package is, kmesh-{version}.tar.gz
  [root@dev tmp]# mv Kmesh kmesh-1.0.0
  [root@dev tmp]# tar zcvf /root/rpmbuild/SOURCES/kmesh-1.0.0.tar.gz kmesh-1.0.0/
  
  # kmesh.spec is stored in /root/rpmbuild/SPEC
  [root@dev kmesh-1.0.0]# cp kmesh.spec /root/rpmbuild/SPECS/
  ```

- rpm build

  ```sh
  [root@dev tmp]# cd /root/rpmbuild/SPECS/
  [root@dev SPECS]# rpmbuild -bb kmesh.spec
  
  # The compilation result is stored in the /root/rpmbuild/RPM/{arch} directory.
  [root@dev tmp]# cd /root/rpmbuild/RPMS/x86_64/
  [root@dev x86_64]# ll
  total 9.2M
  -rw-r--r--. 1 root root 9.2M Nov  5 11:11 kmesh-1.0.0-1.x86_64.rpm
  [root@dev x86_64]#
  ```

### build docker image

- prerequisite

  - install docker-engine

    ```sh
    [root@dev Kmesh]# yum install docker-engine
    ```

  - Preparation of raw materials

    Before compiling the Kmesh image, prepare the Kmesh.rpm, kmesh.dockerfile, and start_kmesh.sh startup scripts. Place it in a directory;

    The kmesh.dockerfile and start_kmesh.sh files are archived in the code repository directory.

    ```sh
    [root@dev Kmesh]# ll build/docker/
    total 12K
    -rw-r--r--. 1 root root  793 Nov 25 01:31 kmesh.dockerfile
    -rw-r--r--. 1 root root 1.5K Nov 25 10:48 kmesh.yaml
    -rw-r--r--. 1 root root  764 Nov 25 01:31 start_kmesh.sh
    ```

    Put the image raw material in a directory.

    ```sh
    [root@dev docker]# ll
    total 9.2M
    -rw-r--r--. 1 root root 9.2M Nov 25 06:37 kmesh-0.0.1.x86_64.rpm
    -rw-r--r--. 1 root root  793 Nov 25 01:36 kmesh.dockerfile
    -rw-r--r--. 1 root root  764 Nov 25 01:36 start_kmesh.sh
    ```

- Creating an Image

  ```sh
  [root@dev docker]# docker build -f kmesh.dockerfile -t kmesh-0.0.1 .
  ```

  Check the existing Kmesh image in the local image repository：

  ```sh
  [root@dev docker]# docker images
  REPOSITORY            TAG                 IMAGE ID            CREATED             SIZE
  kmesh-0.0.1           latest              e321b18d5fee        4 hours ago         675MB
  ```

## Local start mode

- Download the corresponding version software package of Kmesh

  ```sh
  https://github.com/kmesh-net/kmesh/releases
  ```

- Configure Kmesh service

  ```sh
  # Optional, If you are currently not in a service mesh environment and only want to start Kmesh on a standalone basis, you can disable the ads switch. Otherwise, you can skip this step
  [root@ ~]# vim /usr/lib/systemd/system/kmesh.service
  ExecStart=/usr/bin/kmesh-daemon -enable-kmesh -enable-ads=false
  [root@ ~]# systemctl daemon-reload
  ```

- Start Kmesh service

  ```sh
  [root@ ~]# systemctl start kmesh.service
  # View the running status of Kmesh service
  [root@ ~]# systemctl status kmesh.service
  ```

- Stop Kmesh service

  ```sh
  [root@ ~]# systemctl stop kmesh.service
  ```
