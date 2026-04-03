---
sidebar_position: 1
title: Welcome
last_update:
    date: "2025-02-22"
---

# Welcome to Kmesh: High-Performance and Low Overhead Service Mesh Data Plane

Kmesh leverages eBPF and programmable kernels to offload traffic management to the OS, accelerating service mesh performance. Compared to traditional service meshes, it offers advantages such as low latency, being sidecarless, and low resource consumption.

## Why Kmesh?

- **Superior Performance**: Reduces service mesh latency through kernel-level optimizations
- **Resource Efficiency**: Minimizes overhead by implementing service governance at the OS layer
- **Simplified Operations**: Streamlines service mesh management with kernel-integrated traffic routing
- **Cloud Native Integration**: Seamlessly works with existing cloud-native infrastructure

## Core Benefits

| Benefit                 | Description                                                                  |
| ----------------------- | ---------------------------------------------------------------------------- |
| Latency Reduction       | Direct kernel path routing reduces service-to-service communication overhead |
| Resource Optimization   | Lower CPU and memory usage through OS-layer implementation                   |
| Simplified Architecture | Fewer hops in service access paths improve overall performance               |

In the following docs, we will explain:

- The [architecture](/docs/architecture/) and highlights advantages of Kmesh.
- The [quick start](/docs/setup/quick-start) of Kmesh.
- The [performance](/docs/performance/) of Kmesh.
- The [community](/docs/community/contribute.md) of Kmesh.
