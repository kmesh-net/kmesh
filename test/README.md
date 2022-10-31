# Kmesh测试框架介绍

## 什么是mugen

mugen是openEuler社区开放的测试框架，提供公共配置和方法以便社区开发者进行测试代码的编写和执行；Kmesh基于mugen实现了自己的测试框架，以看护Kmesh基本功能稳定。

关于mugen的详细介绍请参考：

https://gitee.com/openeuler/mugen

## Kmesh测试框架简介

Kmesh基于mugen实现了测试框架，主要用于开发阶段，对Kmesh的基本功能做基本保障，确保合入的代码不会对Kmesh的主体功能产生破坏；测试框架代码在`test`目录下，关键文件/目录说明：

```sh
├─runtest.sh	# 测试框架执行脚本
│
├─testcases		# 测试套
│  │  kmesh.json	# 指定要执行kmesh下的哪些测试例，需要与测试例目录名称一致
│  │
│  └─kmesh
│      ├─libs	# 基础库
│      │      common.sh		# 基础库脚本，测试例中引用
│      ├─oe_test_base_function	# 一个测试例一个文件夹
│      │  │  oe_test_base_function.sh	# 测试脚本
│      │  │
│      │  └─conf	# 配置文件
│      │          test_conf.json	# 该测试例对应的xds治理模型
│      │
│      └─pkg	# 测试依赖的外部工具归档
│              fortio-1.38.1-1.x86_64.rpm
│
└─testframe		# 测试框架包
        mugen-master.zip
```

## 如何进行Kmesh测试

- 测试前准备工作

  - 准备一套linux开发环境（如：openEuler 2203 LTS）

  - 替换包含Kmesh增强patch的kernel系列包（kernel.rpm、kernel-devel.rpm、kernel-header.rpm）

    - 如何构建包含Kmesh增强patch的kernel系列包参见：xxx

  - 下载Kmesh代码

    ```sh
    # git clone https://gitee.com/openeuler/Kmesh.git
    ```

- 执行Kmesh测试框架

  ```sh
  [root@dev Kmesh]# cd test/
  [root@dev test]# ./runtest.sh {env_ip} {login_password}
  # runtest的主要步骤：
  # 1 执行安装依赖
  # 2 编译Kmesh代码 + Kmesh.ko，并安装
  # 3 挨个执行测试套中的每个测试例
  # 4 输出测试执行结果，如下
  Tue Oct 25 19:29:50 2022 - INFO  - 配置文件加载完成...
  Tue Oct 25 19:29:51 2022 - INFO  - start to run testcase:oe_test_normal_function.
  Tue Oct 25 19:29:59 2022 - INFO  - The case exit by code 0.
  Tue Oct 25 19:29:59 2022 - INFO  - End to run testcase:oe_test_normal_function.
  Tue Oct 25 19:29:59 2022 - INFO  - A total of 1 use cases were executed, with 1 successes and 0 failures.
  the following test cases run successful
  --------------------------------------->
  oe_test_normal_function
  <---------------------------------------
  [root@localhost test]#
  ```

  test结果中可以看到成功失败的用例数。

- 如何查看测试过程信息

  - 测试过程中的临时文件查看

    测试脚本中，可能会写一些临时文件，并根据临时文件信息做测试结果校验，tmp文件是按测试例粒度归档的；

    ```sh
    # 以kmesh的oe_test_normal_function测试例为例，tmp文件目录：
    [root@localhost test]# ./mugen-master/testcases/smoke-test/kmesh/oe_test_normal_function/
    ```

  - 如何检查具体失败信息

    根据测试结果的失败用例名，找到失败用例的执行日志：

    ```sh
    # 1 以kmesh的oe_test_normal_function测试例为例
    [root@localhost test]# cd mugen-master/logs/kmesh/oe_test_normal_function/
    [root@localhost oe_test_normal_function]# ll
    total 12K
    -rw-r--r--. 1 root root 9.0K Oct 25 19:29 2022-10-25-19:29:51.log
    [root@localhost oe_test_normal_function]#
    # 2 log日志中搜索 CHECK_RESULT，找到 actual_result与expect_result不一致的校验项就是出问题的点
    + CHECK_RESULT 0 0 0 'insmod kmesh.ko failed'
    + actual_result=0
    + expect_result=0
    + mode=0
    ```

## 测试框架基础库介绍

libs目录封装了Kmesh测试过程中的一些公共操作，以简化新增测试例的开发；基础库包含的API列表如下：

- start_fortio_server

  - 功能说明

    启动fortio_server测试程序；

  - 参数说明

    | 参数 |                             含义                             | 必选 |
    | :--: | :----------------------------------------------------------: | :--: |
    |  $1  | 指定fortio_server启动的ip:port；若不指定，默认127.0.0.1:8080 |  N   |
    
  - 调用样例

    ```sh
    # 启动默认fortio_server
    start_fortio_server
    
    # 启动指定ip:port的fortio_server
    start_fortio_server 192.168.100.19:8081
    ```

- start_kmesh

  - 功能说明

    按本地模式启动Kmesh，该模式无需环境部署k8s/istio；

  - 参数说明

    NA

  - 调用样例

    ```sh
    # 按本地模式启动Kmesh
    start_kmesh
    ```

- load_kmesh_config

  -  功能说明

    加载xds配置文件；默认按测试例下的conf加载

  - 参数说明

    NA

  - 调用样例

    ```sh
    load_kmesh_config
    ```

- cleanup

  - 功能说明

    测试清理；

  - 参数说明

    NA

  - 调用样例

    ```sh
    cleanup
    ```

## 如何新增测试用例

- 新增测试例目录

  ```sh
  [root@dev kmesh]# pwd
  /home/Kmesh/test/testcases/kmesh
  [root@dev kmesh]# tree oe_test_lb_policy_function/
  oe_test_lb_policy_function/	# 1 新增测试例文件夹
  ├── conf	
  │   └── test_conf.json	# 2 配套的xds配置文件
  └── oe_test_lb_policy_function.sh	# 3 定义测试脚本
  
  1 directory, 2 files
  [root@dev testcases]# pwd
  /home/Kmesh/test/testcases
  [root@dev testcases]# vim kmesh.json
  {
      "path": "$OET_PATH/testcases/smoke-test/kmesh",
      "cases": [
          {
              "name": "oe_test_base_function"
          },
          {
              "name": "oe_test_lb_policy"	# 增加测试例到测试套中
          }
      ]
  }
  ```