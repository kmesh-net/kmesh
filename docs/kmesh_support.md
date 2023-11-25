### Native support all feature

We can directly compile and run all features of Kmesh in the following OS.

| OS Version      | Kernel Version | Release Path                                |
| :-------------: | :------------: | :-----------------------------------------: |
| openEuler-23.03 |     6.1.19     | https://repo.openeuler.org/openEuler-23.03/ |

### Kmesh enhance kernel support all feature

In the following OS, we can incorporate Kmesh kernel patches into the corresponding kernel of these OS, and then recompile the kernel. After installing the kernel containing the Kmesh kernel patches, we can compile and run all features of Kmesh. The method to build kernel package that supports Kmesh, see [Kmesh kernel compilation](kmesh_kernel_compile.md).

|        OS Version         | Kernel Version |                   OS Release Path                   |
| :-----------------------: | :------------: | :-------------------------------------------------: |
|  openEuler-22.03-LTS-SP1  |     5.10.0     | https://repo.openeuler.org/openEuler-22.03-LTS-SP1/ |
| Ubuntu Server 22.04.3 LTS |     5.15.0     |         https://releases.ubuntu.com/jammy/          |

### Native support partial features

In the following OS, we can compile and run the specific features listed in the table in the corresponding OS.

| OS Version                | Kernel Version | Sockmap Accelerate   | L4 Proxy | L7 Proxy |
| :-----------------------: | :------------: | :------------------: | :------: | :------: |
| Ubuntu Server 22.04.3 LTS |     5.15.0     |           √          |     √    |          |
| openEuler-22.03-LTS-SP1   |     5.10.0     |           √          |     √    |          |

**OS release path**:

- openEuler: https://repo.openeuler.org/
- Ubuntu: https://releases.ubuntu.com/

**Note**: The above listed OS versions have been verified by Kmesh community, which does not mean that other OS versions are not supported, Kmesh community will continue to refresh the supported list.
