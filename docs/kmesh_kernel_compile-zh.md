# Kmesh内核构建

## 背景说明

Kmesh基于内核做了增强，如果想要使用Kmesh，需要自行构建内核包；

本篇主要描述通过patch构建包含Kmesh增强特性的内核包的过程；

## 基于增强特性patch构建内核包

### 增强特性patch说明

Kmesh项目仓中，针对主流内核版本已归档了对应的patch；

```sh
[root@dev Kmesh]# tree kernel/
kernel/
├── ko
├── ko_src
└── patches		# 内核增强特性补丁
    └── 5.10.0	# 基于linux 5.10制作的增强patch
        └── 0001-bpf-sockmap-add-extra-return-value-for-sockops.patch
        └── 0002-xxx.patch
        └── ......
    	└── bpf-support-writable-context-for-bare-tracepoint.patch	#该补丁为社区补丁，在linux 5.16引入，在此之前版本需要判断是否已回合该补丁并按需回合；此补丁提供了kmesh所依赖内核功能相关宏定义
```

内核构建时，按需获取/适配patch。

### 基于linux 5.10 版本构建

以openEuler 2203 LTS SP2 版本(linux 5.10)内核基线为例，构建步骤如下；

- 准备一台x86的编译环境

- 增加openEuler 2203 source repo源

  ```sh
  # /etc/yum.repos.d/openEuler.repo中增加repo源
  [oe_2203_source]
  name=oe_2203_source
  baseurl=https://repo.openeuler.org/openEuler-22.03-LTS-SP2/source/
  enabled=1
  gpgcheck=0
  ```

- 下载基线内核源码包 & 解压

  ```sh
  [root@dev test]# yum download --source kernel.src
  # 基线代码解压缩
  [root@dev test]# rpm -ivh kernel-5.10.0-153.12.0.92.oe2203sp2.src.rpm --root=/home/test/kmesh_kernel
  ```

- patch拷贝到编译目录下

  ```sh
  # 将项目仓中patch拷贝到SOURCE目录下
  [root@dev SOURCES]# pwd
  /home/test/kmesh_kernel/root/rpmbuild/SOURCES
  [root@dev SOURCES]# cp 0001-bpf-sockmap-add-extra-return-value-for-sockops.patch .
  ......
  [root@dev SOURCES]# cp xxx.patch .
  ```

- 修改SPEC增加patch

  ```sh
  # 修改SPEC/kernel.spec 增加如下patch编译内容
  # a. kabi检查可以先关闭
  %define with_kabichk 0
  
  # b. spec中增加patch定义
  # 增加增强特性补丁
  Source9003: 0001-bpf-sockmap-add-extra-return-value-for-sockops.patch
  Source900X: ......
  
  # c. %prep中增加打patch步骤
  patch -s -F0 -E -p1 --no-backup-if-mismatch -i %{SOURCE9003}
  patch -s -F0 -E -p1 --no-backup-if-mismatch -i ......
  ```

- 编译

  ```sh
  # 安装rpmbuild工具
  [root@dev rpmbuild]# yum install -y rpm-build
  # 编译内核包
  [root@dev rpmbuild]# rpmbuild --define="_topdir /home/test/kmesh_kernel/root/rpmbuild" -bb SPECS/kernel.spec
  ```

## QA

### 内核编译依赖包缺失

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
# 依次安装编译依赖包
[root@dev rpmbuild]# yum install -y {依赖包}
```

### char \*不认识的符号类型

```sh
Unrecognized type 'char *', please add it to known types!
make[3]: *** [Makefile:182: /home/test/kmesh_kernel/root/rpmbuild/BUILD/kernel-5.10.0/linux-5.10.0-153.12.0.92.x86_64/tools/bpf/resolve_btfids/libbpf/bpf_helper_defs.h] Error 1
```

A:

```sh
# bpf_helpers_doc.py中增加 char *定义
[root@dev rpmbuild]# vim ./BUILD/kernel-5.10.0/linux-5.10.0-153.12.0.92.x86_64/scripts/bpf_helpers_doc.py
known_types = {
            '...',
            'char *', 

# 修改后增加 --noclean --noprep参数做rpmbuild，否则BUILD目录会重建
[root@dev rpmbuild]# rpmbuild --noclean --noprep --define="_topdir /home/test/kmesh_kernel/root/rpmbuild" -bb SPECS/kernel.spec
```


### Kmesh 新增的patch修改了include/uapi/linux/bpf.h， 和libbpf中的中的bpf.h头文件不再一致。

A:

```sh
#更新libbpf中的bpf.h头文件为kernel中打上patch后的文件；请更新之前备份，用于后续不再使用此版本内核时恢复。
[root@dev rpmbuild]# cp /usr/include/linux/bpf.h /usr/include/linux/bpf.hbak
[root@dev rpmbuild]# cp /home/test/kmesh_kernel/root/rpmbuild/BUILD/kernel-5.10.0/linux-5.10.0-153.12.0.92.x86_64/include/uapi/linux/bpf.h /usr/include/linux/bpf.h

#当然也可以不备份，后续恢复采用重新安装libbpf rpm包的方式

```

