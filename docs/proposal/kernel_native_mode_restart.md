# Kernel-Native Mode Restart Configuration Persistence

## Overview

Kmesh supports uninterrupted acceleration capabilities during restarts and automatically manages related configurations.

## Motivation

Using Kmesh for network acceleration in a K8s cluster, ensuring that acceleration capabilities remain uninterrupted during Kmesh restart scenarios provides a significant competitive advantage through seamless restarts and upgrades.

### Objectives

1. Persistently save related configurations locally during Kmesh restart and automatically manage them to maintain uninterrupted acceleration capabilities.
2. Automatically restore related configurations and update them after a restart.

### Proposal

Implement configuration persistence management and service continuity.

#### Configuration Persistence Management

- Determine if Kmesh is shutting down normally or restart. If it's a restart, persist relevant configurations to a specified directory.
- Persist the eBPF programs used for service traffic management, allowing independent traffic governance even after Kmesh shuts down, thus ensuring service continuity.
- Persist other relevant functional configurations:
  - Management features: Automatically pull the latest configurations and refresh them after each restart.
  - Certificate subscription: Reacquire certificates after each restart.

#### Configuration Restoration and Update

- On Kmesh startup, determine if it is a fresh start or a restart. If it’s a restart, restore configurations from the specified directory and compare them with the latest received configurations for updates.

### Limitations

Currently, upgrade scenarios are not supported but will be in the future.

If Kmesh experiences a coredump leading to a restart, configuration persistence capabilities cannot be achieved.

## Design Details

### Configuration Persistence Management

<div align="center">

![kernel_native_mode_restart](pics/kernel_native_mode_restart.svg)

</div>

- `ebpf_prog` is used for traffic governance operations after Kmesh shuts down.
- `ebpf_map` records configurations for traffic governance operations after Kmesh shuts down.
- `hashName` records the hash value of each XDS configuration tree for comparison to detect changes.
- `Kmesh_version` records the version information of Kmesh for comparing whether Kmesh is in a restart or upgrade state.
- `tail_call_map` tracks eBPF tail call information, recording tail call programs.

#### Persistence Operations

- `ebpf_prog` with `sockconn`, `sockops`, and `tracepoint` ensures that eBPF traffic governance capabilities remain uninterrupted after being solidified.
  
  - Use `bpf_link` to pin the attached `sockconn`/`sockops` programs.
  
  - Directly pin the tracepoint programs to the specified directory.
- Pin other eBPF maps directly to the specified directory.
  
  - Special design: The `ebpf_tail_call` map requires special handling; it must be separately pinned to the file directory.

This functional eBPF ensures that after Kmesh shuts down, traffic governance rules continue to be applied based on existing rules.

- Pin `Kmesh_version` to the specified directory.
  
  - This `ebpf_map` primarily records the Kmesh version and serves as a basis for determining whether to read from the specified directory or treat it as a new start.

- `hashName` serializes and saves the hash of the cached XDS configuration to a file in the `/mnt` directory for comparison after a restart.

### Configuration Restoration and Update

1. Load eBPF programs after a restart.

   1. Restore `Kmesh_version` from the specified directory to determine if it is a restart scenario and whether configuration restoration is needed.

   2. Restore `inner_map_mng` information from the specified directory and update fd information based on the `inner_map` id.

   3. Restore `bpf_map` from the pinned specified directory and restore the tail call map.

   4. Start new eBPF programs for `sockconn`/`sockops`, attach them, update and replace the programs in `bpf_link`, and refresh `tail_call_map`, replacing the old tail call programs for seamless replacement.

   5. After starting the new tracepoint eBPF programs, attach them and then delete the old ones to complete the replacement.

2. Compare saved old data with newly acquired data and refresh.

   During the Kmesh startup process, all XDS configurations will be fully subscribed, and `bpf_map` will be updated through a complete overwrite. Therefore, for new and updated XDS configurations, they will be loaded into `bpf_map`, and we only need to consider deletions during the restart process.

   Restore the XDS configuration tree from the `/mnt` directory to a variable and compare it with the latest subscribed XDS configuration cache. Remove records that exist in the persisted file but not in the cache to ensure the accuracy of the `bpf_map` configuration.

### Outstanding Issues

1. The current refresh granularity for the XDS tree is at the top-level config. Future iterations will refine this granularity.
2. Coordination between other single-point features and restart functionality remains to be considered.