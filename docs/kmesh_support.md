### Kmesh-capable OS

Kmesh requires kernel eBPF functionality and sizeable eBPF Instruction Sets, so Kmesh can only run on operating systems above a certain version.

Kmesh has two different modes, `Kernel-Native Mode` and `Duel-Engine Mode`. Although there is no difference between the two modes in terms of the os kernel version required, we still described separately in the table below.

| Mode | OS Version | Kernel Version | Release Path |
| :-------------: | :-------------: | :-------------: | :-------------: |
| Kernel-Native Mode | openEuler-23.03 | 6.1.19 | https://repo.openeuler.org/openEuler-23.03/ |
|                    | openEuler-22.03-LTS-SP1 |     5.10.0     | https://repo.openeuler.org/openEuler-22.03-LTS-SP1/ |
|                    | Ubuntu Server 22.04.3 LTS |     5.15.0   |         https://releases.ubuntu.com/jammy/          |
| Duel-Engine Mode | openEuler-23.03 | 6.1.19 | https://repo.openeuler.org/openEuler-23.03/ |
|                    | openEuler-22.03-LTS-SP1 |     5.10.0     | https://repo.openeuler.org/openEuler-22.03-LTS-SP1/ |
|                    | Ubuntu Server 22.04.3 LTS |     5.15.0   |         https://releases.ubuntu.com/jammy/          |

**Note:** The above is the version of OS that we have actually tested to deploy Kmesh successfully. Kmesh can actually be deployed on any OS with a kernel version greater than **5.10**. And we welcome you to help the community improve this table based on your actual OS deployment of Kmesh.
