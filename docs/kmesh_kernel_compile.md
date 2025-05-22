# Kmesh kernel build

## Background

Kmesh has enhanced some features based on the kernel,  if you want to use Kmesh, you need to build the kernel package yourself.

This article mainly describes the process of building a kernel package with Kmesh enhanced features through patch.

## Building Kernel Package Based on Enhanced Feature Patch

### Description of the Enhanced Feature Patch

Patches corresponding to the mainstream kernel version have been archived in the Kmesh project repository.

```sh
[root@dev Kmesh]# tree kernel/
kernel/
├── ko
├── ko_src
└── patches  # Kernel enhancement feature patches 
    └── 5.10.0 # Enhancement patch made based on Linux 5.10
        └── 0001-add-helper-strnstr-strncmp-parse_header_msg.patch
        └── 0002-add-TCP_ULP-support-in-bpf_getset_sockopt.patch
```

When building the kernel, get/adapt the patch as needed.

### Building on linux 5.10

Taking openEuler 2203 LTS SP2（linux 5.10）as an example, the build steps as follows:

- Prepare an x86 compilation environment

- Add openEuler 2203 source repo source

  ```sh
  # Add repo source in /etc/yum.repos.d/openEuler.repo
  [oe_2203_source]
  name=oe_2203_source
  baseurl=https://repo.openeuler.org/openEuler-22.03-LTS-SP2/source/
  enabled=1
  gpgcheck=0
  ```

- Download baseline kernel source package & decompress

  ```sh
  [root@dev test]# yum download --source kernel.src
  # Decompress baseline code
  [root@dev test]# rpm -ivh kernel-5.10.0-153.12.0.92.oe2203sp2.src.rpm --root=/home/test/kmesh_kernel
  ```

- Copy patch to compile directory

  ```sh
  # Copy the patch from the project repository to the SOURCE directory
  [root@dev SOURCES]# pwd
  /home/test/kmesh_kernel/root/rpmbuild/SOURCES
  [root@dev SOURCES]# cp 0001-bpf-sockmap-add-extra-return-value-for-sockops.patch .
  [root@dev SOURCES]# cp 0002-add-TCP_ULP-support-in-bpf_getset_sockopt.patch .
  ```
  
- Modify SPEC to add patch

  ```sh
  # Modify SPEC/kernel.spec to add patch compilation
  # a. kabi check can be turned off first
  %define with_kabichk 0
  
  # b. add patch definition in spec
  # add enhancement feature patch
  Source9003: 0001-add-helper-strnstr-strncmp-parse_header_msg.patch
  Source9004: 0002-add-TCP_ULP-support-in-bpf_getset_sockopt.patch
  
  # c. %prep add apply patch step
  patch -s -F0 -E -p1 --no-backup-if-mismatch -i %{SOURCE9003}
  patch -s -F0 -E -p1 --no-backup-if-mismatch -i %{SOURCE9004}
  ```

- Compile

  ```sh
  # Install rpmbuild
  [root@dev rpmbuild]# yum install -y rpm-build
  # Compile kernel package
  [root@dev rpmbuild]# rpmbuild --define="_topdir /home/test/kmesh_kernel/root/rpmbuild" -bb SPECS/kernel.spec 
  ```

## QA

### Kernel compilation dependency package is missing

```sh
[root@dev rpmbuild]# rpmbuild --define="_topdir /home/test/kmesh_kernel/root/rpmbuild" -bb SPECS/kernel.spec
warning: line 153: It's not recommended to have unversioned Obsoletes: Obsoletes: kernel-tools-libs
warning: line 168: It's not recommended to have unversioned Obsoletes: Obsoletes: kernel-tools-libs-devel
warning: bogus date in %changelog: Tue Jan 29 2021 Yuan Zhichang <erik.yuan@arm.com> - 5.10.0-1.0.0.10
error: Failed build dependencies:
        asciidoc is needed by kernel-5.10.0-153.12.0.92.x86_64
        audit-libs-devel is needed by kernel-5.10.0-153.12.0.92.x86_64
        bc is needed by kernel-5.10.0-153.12.0.92.x86_64
        ......
[root@dev rpmbuild]#
```

A：

```sh
# Install the compilation dependency packages
[root@dev rpmbuild]# yum install -y {dependency package}
```

### Unrecognized type 'char *'

```sh
Unrecognized type 'char *', please add it to known types!
make[3]: *** [Makefile:182: /home/test/kmesh_kernel/root/rpmbuild/BUILD/kernel-5.10.0/linux-5.10.0-153.12.0.92.x86_64/tools/bpf/resolve_btfids/libbpf/bpf_helper_defs.h] Error 1
```

A:

```sh
# Add char * Definition in bpf_helpers_doc.py
[root@dev rpmbuild]# vim ./BUILD/kernel-5.10.0/linux-5.10.0-153.12.0.92.x86_64/scripts/bpf_helpers_doc.py
known_types = {
            '...',
            'char *', 

# After modification, add --noclean --noprep parameters to do rpmbuild, otherwise the BUILD directory will be rebuilt
[root@dev rpmbuild]# rpmbuild --noclean --noprep --define="_topdir /home/test/kmesh_kernel/root/rpmbuild" -bb SPECS/kernel.spec
```

### Kmesh's new patch has modified include/uapi/linux/bpf.h, and it is no longer consistent with the bpf.h header file in libbpf

A:

```sh
# Update the bpf.h header file in libbpf to the file after the kernel is patched; please back up before updating, for subsequent recovery when this version of the kernel is no longer used.
[root@dev rpmbuild]# cp /usr/include/linux/bpf.h /usr/include/linux/bpf.hbak
[root@dev rpmbuild]# cp /home/test/kmesh_kernel/root/rpmbuild/BUILD/kernel-5.10.0/linux-5.10.0-153.12.0.92.x86_64/include/uapi/linux/bpf.h /usr/include/linux/bpf.h

# Of course, you can also not back up, and the subsequent recovery will be done by reinstalling the libbpf rpm package.

```
