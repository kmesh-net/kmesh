---
title: Kmesh-daemon upgrades traffic without disruption
authors:
- "@072020127"
reviews:
-
approves:
-

create-date: 2025-07-08

---

## Kmesh-daemon upgrades traffic without disruption

### Summary

Add traffic-preserving upgrades to Kmesh-daemon.

### Motivation

Currently, Kmesh supports traffic-preserving restarts but does not support traffic-preserving upgrades. During upgrades, existing eBPF map state may be discarded if the map definitions change, leading to connection drops, policy resets, or performance metric loss.

This proposal improves the upgrade experience by:

- Preserving important state (flows, policies, metrics) across versions
- Allowing safe, autonomous rolling upgrades in Kubernetes environments
- Reducing operational risk and improving reliability in production deployments

### Goals

The purpose of this proposal is to enable seamless traffic continuity during version upgrades by detecting map changes and migrating data safely.

### Design Details

#### Map Compatibility Detection

1. **Runtime Inspection**: The comparison logic begins by loading each map’s runtime `MapSpec` which includes `MapType`, `KeySize`, `ValueSize`, `MaxEntries` , `Key` and `Value`.
1. **Spec Snapshot at Startup**: During Kmesh-daemon startup, each `MapSpec` generated from the compiled BPF object is stored in a user-space registry for future comparison. On Update-type startup, the daemon reads the previous version’s stored `MapSpec` definitions and uses them as the baseline `oldMapSpec` for diff comparison.
1. **Layout Diffing**: A recursive comparison (`diffBTFStructFieldsRec`) examines field name, type, and byte offset, supporting nested struct types. Any difference in metadata or BTF layout triggers a migration path.

#### Data Migration Logic

1. **New Map Creation**: When a layout change is detected, a new map is created based on the latest `MapSpec`, with its path set to the old map path appended with "_tmp", and temporarily pinned to an alternate location. 
2. **Dual-Write Wrapper**: The daemon wraps all map update logic so that every write operation is simultaneously issued to both the old and new maps, only when Kmesh-daemon is upgrading.
3. **Data Migration**: Entries are iterated from the old map and copied using `convertStructValue`, which transfers only matching fields and sets defaults for missing or incompatible ones. The logic handles two strategies: 
   - if key or type has changed, the old map is discarded and a new one is started fresh.
   - if value layout has changed but keys remain compatible, entries are fully migrated. 
4. **Atomic Pin Swap**: Once data migration completes, the daemon proceeds to unpin the old map. It then closes the old map’s file descriptor, attempts to remove the old map’s pin file, and finally renames the temporary pinned path of the new map to the original map’s pin path. 

#### Hot Program Replacement

1. **Atomic Swap**: Once all maps are migrated, new BPF programs are attached. The upgrade process uses `link.Update` to atomically swap the loaded program with a new one. This approach ensures there is no packet loss during the transition.

#### Testing Plan

1. **Unit Tests**: Validate `diffBTFStructFieldsRec`, `convertStructValue`, and the dual-write synchronization.
2. **E2E Tests**: Run Kmesh upgrades with live traffic and verify data continuity, no packet loss, and zero connection resets.
