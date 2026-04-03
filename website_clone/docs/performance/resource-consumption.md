---
title: Kmesh Resource Consumption
sidebar_position: 2
---

# Kmesh Resource Consumption

## Background Information

eBPF programs consume CPU and memory resources during execution. To better understand Kmesh's resource consumption under different workloads, we conducted several CPU and memory stress tests. These tests evaluate the limits of Kmesh's resource consumption in real-world usage scenarios.

**Note: This documentation is based on Kmesh 0.4 kernel-native mode**

## Environment Setup

![Resource test environment](./images/resource_test_env.png)

| Component         | Version/Details                                                                                                       |
| ----------------- | --------------------------------------------------------------------------------------------------------------------- |
| K8S               | v1.27                                                                                                                 |
| Kmesh             | 0.4 kernel-native mode                                                                                                |
| Kernel            | 5.10                                                                                                                  |
| Node              | 8U16G                                                                                                                 |
| Testing tool      | fortio                                                                                                                |
| Metric collection | [bpftop](https://github.com/Netflix/bpftop), [inspektor-gadget](https://github.com/inspektor-gadget/inspektor-gadget) |

## Test Case 1: POD with CPU Limit

### Scenario 1.1: Single App with CPU Limit

![Resource test 1](./images/resource_test1.png)

We set a CPU limit of 1 (1 CPU) for App A and collected the corresponding Kmesh eBPF CPU consumption.

:::note
With the system having 8 cores and a CPU limit of 1, the POD can consume up to 12.5% of the total CPU.
:::

**Test Procedure:**

1. Generated load using the fortio client:

   ```bash
   # !/bin/bash

   client_address=`kubectl get pod | grep fortio-client | awk {'print $1'}`
   echo "$client_address" | xargs -P 0 -I {} kubectl exec -it {} -- fortio load -quiet -c 1500 -t 100s -qps 0 -keepalive=false fortio-server.default.svc.cluster.local:80
   ```

2. Collected CPU usage with bpftop:

   ```bash
   ./bpftop
   ```

**Test Results:**

![Resource result 1](./images/resource_test_result1.png)

The 12.99% shown in the figure means that 12.99% of one CPU core was consumed.

**Conclusion:**
When App A fully utilizes one CPU core, the eBPF program consumes 1.73% of the CPU (13.9% usage of one CPU core = 1.73% of 8 CPU cores), which is less than the POD CPU limit of 12.5%. There are two possible explanations:

- App A and Kmesh eBPF share the POD CPU limit, with Kmesh eBPF CPU being restricted by the POD CPU limit
- The eBPF CPU cost is relatively small compared to the application itself, and App A is not generating enough load to cause eBPF to exceed the CPU limit

### Scenario 1.2: Multiple Apps with CPU Limits

![Resource test 2](./images/resource_test2.png)

We deployed 4 instances of App A, with a CPU limit of 250m for each instance, totaling 1 CPU for all 4 instances.

**Test Results:**

![Resource result 2](./images/resource_test_result2.png)

The 13.42% shown in the figure means that 13.42% of one CPU core was consumed.

**Conclusion:**
When App A fully utilizes one CPU, the eBPF program consumes 1.81% of the CPU, which is less than the POD CPU limit of 12.5%.

### Scenario 1.3: Modified eBPF Code to Increase CPU Usage

We modified the eBPF code to decrease its performance, causing it to consume more CPU, to observe if it could exceed the POD CPU limit.

**Implementation:**
Added a for loop in the Kmesh eBPF code:

```c
SEC("cgroup/connect4")
int cgroup_connect4_prog(struct bpf_sock_addr *ctx)
{
    struct kmesh_context kmesh_ctx = {0};
    kmesh_ctx.ctx = ctx;
    kmesh_ctx.orig_dst_addr.ip4 = ctx->user_ip4;
    kmesh_ctx.dnat_ip.ip4 = ctx->user_ip4;
    kmesh_ctx.dnat_port = ctx->user_port;

    if (handle_kmesh_manage_process(&kmesh_ctx) || !is_kmesh_enabled(ctx)) {
        return CGROUP_SOCK_OK;
    }

    // Add for loop to increase CPU usage
    int i;
    for (i = 0; i < 65535; i++) {
        bpf_printk("increase cpu usage");
    }

    int ret = sock4_traffic_control(ctx);
    return CGROUP_SOCK_OK;
}
```

**Test Results:**

![Resource result 3](./images/resource_test_result3.png)

When App A fully utilizes one CPU, the eBPF program consumes up to 12.1% of the CPU, which is still less than the POD CPU limit of 12.5%. After multiple rounds of testing, the eBPF's CPU consumption consistently remained below the POD CPU limit.

**Conclusion:**
Kmesh eBPF and the application share the POD CPU limit, with Kmesh eBPF CPU being constrained by the POD CPU limit.

## Test Case 2: Scenarios without POD CPU Limits

### Scenario 2.1: Testing eBPF CPU Consumption without Limits

![Resource test 3](./images/resource_test3.png)

We created 8 instances of App A with no CPU limits. We gradually increased the number of processes generating load for App A until the node's CPU usage reached 100%, then collected the CPU usage of Kmesh eBPF.

**Test Results (8-core CPU totaling 8000m):**

| Threads | App A CPU Usage | eBPF CPU Usage |
| ------- | --------------- | -------------- |
| 100     | 12.3%           | 1%             |
| 500     | 35%             | 4.1%           |
| 1000    | 61.7%           | 8.8%           |
| 3000    | 67%             | 9.5%           |

With 3000 concurrent processes, the node reached 100% CPU utilization. At this point, App A consumed 67% of the CPU, while Kmesh eBPF consumed approximately 9.5%.

**Conclusions:**

- App A consumes significantly more CPU than eBPF, making it difficult to overload eBPF. In scenarios tested with Fortio, Kmesh eBPF consumed a maximum of 9.5% CPU.
- Further testing is needed to determine the maximum CPU consumption limit for eBPF itself.

### Scenario 2.2: eBPF CPU Stress Test

The [eBPF official documentation](https://ebpf-docs.dylanreimerink.nl/linux/concepts/verifier/) indicates that eBPF programs have robust security mechanisms that automatically detect infinite loops and strictly limit the number of iterations in for loops. In the current Kernel version (v5.10), eBPF programs support a maximum of 65,535 iterations in for loops.

We added 65,535 iterations to the for loop and tested it:

```c
SEC("cgroup/connect4")
int cgroup_connect4_prog(struct bpf_sock_addr *ctx)
{
    struct kmesh_context kmesh_ctx = {0};
    kmesh_ctx.ctx = ctx;
    kmesh_ctx.orig_dst_addr.ip4 = ctx->user_ip4;
    kmesh_ctx.dnat_ip.ip4 = ctx->user_ip4;
    kmesh_ctx.dnat_port = ctx->user_port;

    if (handle_kmesh_manage_process(&kmesh_ctx) || !is_kmesh_enabled(ctx)) {
        return CGROUP_SOCK_OK;
    }

    // Add for loop to increase CPU usage
    int i;
    for (i=0;i<65535;i++) {
        bpf_printk("increase cpu usage");
    }

    int ret = sock4_traffic_control(ctx);
    return CGROUP_SOCK_OK;
}
```

**Test Results:**

![Resource result 4](./images/resource_test_result4.png)

When the node's CPU was running at 100%, Kmesh eBPF consumed approximately 99.3% of the CPU. This stress test ran for 10 minutes, during which the kernel and services within the cluster continued to operate stably.

**Conclusion:**
In the Kmesh eBPF component, when adding support for the maximum number of for loop iterations, eBPF can consume all available CPU resources. However, the kernel's security mechanisms ensure the stable operation of the system.

## Kmesh eBPF Memory Limit Test

The memory consumption of eBPF has an upper limit, as stated in the [official documentation](https://ebpf-docs.dylanreimerink.nl/linux/concepts/resource-limit/). This limit is set through the `memory.max` setting in cGroup configurations.

However, based on the current implementation of Kmesh, memory is allocated at the start of Kmesh and does not increase during runtime. We conducted tests to verify the memory usage.

### Test 1: Memory Usage with Varying Service Counts

We created 1, 100, and 1000 services respectively in the cluster and recorded the eBPF memory consumption using [inspektor-gadget](https://github.com/inspektor-gadget/inspektor-gadget).

**Monitoring Command:**

```bash
kubectl gadget top ebpf
```

![Resource result memory](./images/resource_test_memory.png)

**Test Results:**

| Service Count | eBPF Memory Usage |
| ------------- | ----------------- |
| 1             | 23 MB             |
| 100           | 23 MB             |
| 1000          | 23 MB             |

**Conclusion:**
The eBPF memory consumption of Kmesh is consistently 23 MB, regardless of the number of services.

### Test 2: Memory Usage Under Load

We created a service (App A) in the cluster, generated load, and observed eBPF memory consumption.

**Test Results:**
Kmesh eBPF memory consumption remained constant at 23 MB, regardless of the load.
