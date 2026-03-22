---
title: Run Unit test
sidebar_position: 1
---

# Run Unit Test

Compiling Kmesh directly in the operating system requires a certain [OS version](https://github.com/kmesh-net/kmesh/blob/main/docs/kmesh_support.md). Therefore, in order to allow all operating systems to run Kmesh's UT, Kmesh provides two ways to do so. One to run the go unit test in docker and one to run the go unit test locally.

Developers of unsupported kernel version can run go unit test in docker through script. Developers of supported version can run go unit test locally through script.

```sh
cd $(Kmesh root directory)

# Run kmesh ut through docker
./hack/run-ut.sh --docker

# Run kmesh ut locally
./hack/run-ut.sh --local
```

Alternatively, you can execute the test by `make test`:

```sh
# Run kmesh ut through docker
make test RUN_IN_CONTAINER=1

# Run kmesh ut locally
make test RUN_IN_CONTAINER=0
```

## Unit test

This section describes the ut settings for Kmesh so that developers can run unit tests without using scripts.

Because Kmesh uses eBPF, you need to set some environment variables when running Kmesh-related Unit Tests.

```sh
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib:$ROOT_DIR/api/v2-c:$ROOT_DIR/bpf/deserialization_to_bpf_map
export PKG_CONFIG_PATH=$ROOT_DIR/mk
```

Set `LD_LIBRARY_PATH` so that the system can find the .so files.

Set `PKG_CONFIG_PATH` so that the system can find the .pc files that Kmesh compiled.

In addition to this, you may also encounter a c header file not found error. Such errors can be resolved by setting `C_INCLUDE_PATH`. The header files needed for Kmesh are saved in the [bpf](https://github.com/kmesh-net/kmesh/tree/main/bpf) folder.

Note the **multiple header file** problem.

### Common Issues and Solutions for Running Unit Tests

When running unit tests in the `/test/bpf_ut/bpftest` directory, you might encounter the following issues and their solutions. To avoid repeated settings, it is recommended to use a unified `sudo env` command to execute the tests.

1. **`go` command not found**

    In a `sudo` environment, the `go` command might not be found in the `PATH`.
    * **Solution**: Explicitly pass the `PATH` environment variable in the `sudo` command, e.g., `PATH=$PATH:/usr/local/go/bin`.

2. **Go module download issue (network timeout)**

    For example, encountering `Get "https://proxy.golang.org/..." i/o timeout`. This is usually caused by network proxy or connection problems preventing Go modules from being downloaded.
    * **Solution**: Set `GOPROXY` to use a domestic proxy and disable `GOSUMDB` verification, e.g., `GOPROXY=https://goproxy.cn,direct GOSUMDB=off`.

3. **`No package 'api-v2-c' found`**

    This indicates that `pkg-config` cannot find the `api-v2-c.pc` file.
    * **Solution**: Find the actual path of the `api-v2-c.pc` file and add its directory to the `PKG_CONFIG_PATH` environment variable. In the Kmesh project, this file is usually located in the `mk/` directory.
  
        ```sh
        # Find the .pc file
        find {your-project-path} -name "api-v2-c.pc"
        # Example output: {your-project-path}/mk/api-v2-c.pc
        # Set PKG_CONFIG_PATH
        export PKG_CONFIG_PATH={your-project-path}/mk:$PKG_CONFIG_PATH
        # Verify (optional)
        pkg-config --cflags api-v2-c
        ```

4. **`libkmesh_api_v2_c.so: cannot open shared object file: No such file or directory` (Dynamic library not found)**

    This usually happens at runtime when the system cannot find the `.so` dynamic library file compiled by Kmesh.
    * **Solution**: Determine the directory where the `.so` file is located (e.g., `/usr/lib64`) and add it to the `LD_LIBRARY_PATH` environment variable, e.g., `LD_LIBRARY_PATH=/usr/lib64:$LD_LIBRARY_PATH`.

**Unified Unit Test Execution Command Example**:

To resolve the above common issues, you can use the following command with all necessary environment variables to run unit tests:

```sh
sudo env \
  PKG_CONFIG_PATH={your-project-path}/mk:$PKG_CONFIG_PATH \
  GOPROXY=https://goproxy.cn,direct \
  GOSUMDB=off \
  PATH=$PATH:/usr/local/go/bin \
  LD_LIBRARY_PATH=/usr/lib64:$LD_LIBRARY_PATH \
  make run
```

If you want to see more detailed test output, you can add the `-test.v` parameter:

```sh
sudo env \
  PKG_CONFIG_PATH={your-project-path}/mk:$PKG_CONFIG_PATH \
  GOPROXY=https://goproxy.cn,direct \
  GOSUMDB=off \
  PATH=$PATH:/usr/local/go/bin \
  LD_LIBRARY_PATH=/usr/lib64:$LD_LIBRARY_PATH \
  go test ./bpftest -bpf-ut-path {your-project-path}/test/bpf_ut -test.v
```

Please adjust based on the actual root directory path of your Kmesh project (e.g., `{your-project-path}`) and the path to the `.so` dynamic library file (e.g., `/usr/lib64`).

Besides the above issues, since Kmesh ut uses gomonkey, there may be a situation where monkey's functions are small and inlined during Go compilation optimization.

We can solve this problem by adding the following parameter to the go test execution:

```bash
-gcflags="all=-N -l"
```
