# Introduction to Kmesh Test Framework

## What is Mugen

Mugen is a testing framework open-sourced by the openEuler community. It provides public configurations and methods for community developers to write and execute test code. Kmesh has implemented its own testing framework based on Mugen to ensure the stability of basic Kmesh functions.

For a detailed introduction to Mugen, please refer to:

<https://gitee.com/openeuler/mugen>

## Introduction to Kmesh Test Framework

Kmesh implements a testing framework based on Mugen. It is primarily used during the development phase to ensure the basic functionality of Kmesh and prevent merged code from breaking core features. The testing framework code is located in the `test` directory. Description of key files/directories:

```sh
├─runtest.sh # Test framework execution script
│
├─testcases  # Test suites
│  │  kmesh.json # Specifies which test cases under kmesh to execute; must match the test case directory name
│  │
│  └─kmesh
│      ├─libs # Basic library
│      │      common.sh  # Basic library script, referenced in test cases
│      ├─oe_test_base_function # One folder per test case
│      │  │  oe_test_base_function.sh # Test script
│      │  │
│      │  └─conf # Configuration files
│      │          test_conf.json # The xds governance model corresponding to this test case
│      │
│      └─pkg # Archive of external tools required for testing
│              fortio-1.38.1-1.x86_64.rpm
│
└─testframe  # Test framework package
        mugen-master.zip
```

## How to Run Kmesh Tests

- Pre-test preparation

  - Prepare a Linux development environment (e.g., openEuler 2203 LTS)

  - Replace the kernel series packages containing the Kmesh enhancement patch (kernel.rpm, kernel-devel.rpm, kernel-header.rpm)

    - For instructions on how to build kernel series packages containing the Kmesh enhancement patch, please refer to: [Kmesh Kernel Compile Guide](../docs/en/kmesh_kernel_compile.md)

  - Download Kmesh code

    ```sh
    # git clone https://github.com/kmesh-net/kmesh.git
    ```

- Execute the Kmesh testing framework

  ```sh
  [root@dev Kmesh]# cd test/
  [root@dev test]# ./runtest.sh {env_ip} {login_password}
  # Main steps of runtest:
  # 1 Execute dependency installation
  # 2 Compile Kmesh code and Kmesh.ko, and install
  # 3 Execute each test case in the test suite one by one
  # 4 Output the test execution results, as follows
  Tue Oct 25 19:29:50 2022 - INFO  - Configuration file loaded successfully...
  Tue Oct 25 19:29:51 2022 - INFO  - start to run testcase:oe_test_normal_function.
  Tue Oct 25 19:29:59 2022 - INFO  - The case exit by code 0.
  Tue Oct 25 19:29:59 2022 - INFO  - End to run testcase:oe_test_normal_function.
  Tue Oct 25 19:29:59 2022 - INFO  - A total of 1 use case was executed, with 1 success and 0 failures.
  the following test cases ran successfully
  --------------------------------------->
  oe_test_normal_function
  <---------------------------------------
  [root@localhost test]#
  ```

  You can see the number of successful and failed test cases in the test results.
  
- You can also execute a single test case  

 ```sh
  [root@dev test]# ./runtest.sh {env_ip} {login_password} {testcase_name}
  ```

- How to view test process information

  - View temporary files during the test process

    The test script may write some temporary files and verify the test results based on them. These temporary files are archived at the test case level.

    ```sh
    # Taking the oe_test_normal_function test case of Kmesh as an example, the temporary file directory is:
    [root@localhost test]# ./mugen-master/testcases/smoke-test/kmesh/oe_test_normal_function/
    ```

  - How to check specific failure information

    Based on the failed test case name in the test results, find the execution log of the failed test case:

    ```sh
    # 1 Taking the oe_test_normal_function test case of Kmesh as an example
    [root@localhost test]# cd mugen-master/logs/kmesh/oe_test_normal_function/
    [root@localhost oe_test_normal_function]# ll
    total 12K
    -rw-r--r--. 1 root root 9.0K Oct 25 19:29 2022-10-25-19:29:51.log
    [root@localhost oe_test_normal_function]#
    # 2 Search for CHECK_RESULT in the log file. The verification item where actual_result is inconsistent with expect_result is the point of failure.
    + CHECK_RESULT 0 0 0 'insmod kmesh.ko failed'
    + actual_result=0
    + expect_result=0
    + mode=0
    ```

## Introduction to Test Framework Basic Library

The `libs` directory encapsulates common operations during the Kmesh test process to simplify the development of new test cases. The list of APIs included in the basic library is as follows:

- start_fortio_server

  - Function description

    Start the Fortio server test program.

  - Parameter description

    Consistent with the Fortio server commands.

    However, it should be noted that if you want to modify the port or IP address here, it must be passed in the complete format of IP:port.

  - Call example

    ```sh
    # Start the default fortio_server
    start_fortio_server
    
    # Start the fortio_server with specified ip:port
    start_fortio_server -http-port 192.168.100.19:8081
    
    # Start the specified ip:port and specify parameters to be passed in the header
    start_fortio_server -http-port 192.168.100.19:8081 -echo-server-default-params="server:1"
    ```

- start_kmesh

  - Function description

    Start Kmesh in local mode. This mode does not require deploying Kubernetes or Istio in the environment.

  - Parameter description

    N/A

  - Call example

    ```sh
    # Start Kmesh in local mode
    start_kmesh
    ```

- load_kmesh_config

  - Function description

    Load the xds configuration file. By default, it is loaded according to the conf directory under the test case.

  - Parameter description

    N/A

  - Call example

    ```sh
    load_kmesh_config
    ```

- cleanup

  - Function description

    Test cleanup.

  - Parameter description

    N/A

  - Call example

    ```sh
    cleanup
    ```

## How to Add New Test Cases

- Add a test case directory

  ```sh
  [root@dev kmesh]# pwd
  /home/Kmesh/test/testcases/kmesh
  [root@dev kmesh]# tree oe_test_lb_policy_function/
  oe_test_lb_policy_function/ # 1 Add test case folder
  ├── conf 
  │   └── test_conf.json # 2 Corresponding xds configuration file
  └── oe_test_lb_policy_function.sh # 3 Define test script
  
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
              "name": "oe_test_lb_policy_function" # Add test case to the test suite
          }
      ]
  }
  ```
