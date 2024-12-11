### Support status of Kmesh

Kmesh requires kernel eBPF functionality and sizeable eBPF Instruction Sets, so Kmesh can only run on Kernel version above **5.10**.

Kmesh uses istiod as a control plane and therefore Kmesh has some dependencies on istio versions and kubernetes versions.

Kmesh has two different modes, `Kernel-Native Mode` and `Duel-Engine Mode`. While there is no difference in the OS kernel version required for the two modes, the supported istio versions differ. Therefore we explain them separately.

- **Kmesh Duel-Engine Mode:**

| Version | Request Kernel Version | Supported Istio Version | Support Kubernetes Version |
| :-------------: | :-------------: | :-------------: | :-------------: |
| main | >5.10 | 1.22, 1.23, 1.24 | 1.26, 1.27, 1.28, 1.29, 1.30, 1.31 |
| 0.5 | >5.10 | 1.22, 1.23 | 1.26, 1.27, 1.28, 1.29, 1.30 |
| 0.4 | >5.10 | 1.22, 1.23 | 1.26, 1.27, 1.28, 1.29, 1.30 |
| 0.3 | >5.10 | 1.22 | 1.26, 1.27, 1.28, 1.29, 1.30 |

**Note:** Kmesh's Duel-Engine Mode requires the setting of `pilot.env.PILOT_ENABLE_AMBIENT=true` in istiod. so 1.22+ istio is required!

- **Kmesh Kernel-Native Mode:**

| Version | Request Kernel Version | Supported Istio Version | Support Kubernetes Version |
| :-------------: | :-------------: | :-------------: | :-------------: |
| main | >5.10 | 1.22, 1.23, 1.24 | 1.26, 1.27, 1.28, 1.29, 1.30, 1.31 |
| 0.5 | >5.10 | 1.22, 1.23 | 1.26, 1.27, 1.28, 1.29, 1.30 |
| 0.4 | >5.10 | 1.22, 1.23 | 1.26, 1.27, 1.28, 1.29, 1.30 |
| 0.3 | >5.10 | 1.22 | 1.26, 1.27, 1.28, 1.29, 1.30 |

**Note:**

- 1.`Kernel-Native Mode` does not depend on `pilot.env.PILOT_ENABLE_AMBIENT=true`. It is theoretically compatible with istiod <1.22.
- 2.`Kernel-Native Mode's` L7 functionality requires kernel patches. The exception is the [oe23.03](https://repo.openeuler.org/openEuler-23.03/), which can natively support L7 functionality for Kmesh `Kernel-Native Mode`.
