// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Kmesh */

/* When the two ends use loopback addresses for communication, there is a
 * low probability that link conflicts occur. The namespace cookie
 * corresponding to each container is added to the hash key to avoid
 * loopback address link conflicts. Obtains the namespace cookie of the
 * current container based on the bpf_get_netns_cookie auxiliary function.
 */
#define MDA_LOOPBACK_ADDR 1

/* supports NAT acceleration. That is, acceleration can also be performed
 * when iptables is used to forward traffic between service containers
 * and sidecar containers. The bpf_sk_original_addr auxiliary function is
 * used to obtain the original destination address.
 */
#define MDA_NAT_ACCEL 1

/* supports acceleration function filtering based on GID and UID.
 * That is, the GID or UID corresponding to the process to be accelerated
 * is configured in the configuration file. The bpf_get_sockops_uid_gid
 * auxiliary function is used to obtain the GID and UID of the current
 * process.
 */
#define MDA_GID_UID_FILTER 1

/*
 * in kernel 6.x version, add the new iter type ITER_UBUF, and we need add code
 * for the corresponding scenarios.
 */
#define ITER_TYPE_IS_UBUF 0

/*
 * Kmesh’s Layer 7 acceleration proxy capability relies on kernel enhancements.
 * It’s necessary to determine whether the current environment has an
 * enhanced kernel in order to enable Kmesh’s capabilities.
 */
#define ENHANCED_KERNEL 0

/*
 * Different versions of libbpf can be installed in different environments,
 * and there are some incompatibilities in the function interfaces provided
 * by different versions of libbpf. Considering compatibility issues, a new
 * compilation macro is added. The value of this macro is set according to
 * the libbpf version in the current environment, and the code in the project
 * is enabled accordingly.
 * */
#define LIBBPF_HIGHER_0_6_0_VERSION 0

/*
 * Determine whether the current kernel version supports the use of kfunc.
 */
#define KERNEL_KFUNC 0