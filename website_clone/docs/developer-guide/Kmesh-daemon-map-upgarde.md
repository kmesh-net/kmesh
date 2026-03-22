---
sidebar_position: 4
title: Kmesh daemon maps upgrades traffic without disruption
---

# Project Documentation: Kmesh daemon maps upgrades traffic without disruption

## Current strategy

On upgrade the Kmesh-daemon snapshots the current MapSpec (the `CollectionSpec` embedded by `bpf2go`) to disk. During an upgrade, the daemon reads the previously persisted snapshot as oldMapSpec and performs a strict comparison with the current MapSpec. If the maps are detected as compatible (same type and layout), the daemon reuses the existing pinned map. If they are incompatible, the daemon does not attempt complex live migration; instead it creates a new empty map which is initially pinned to a temporary path and then atomically replaces the original pin by unpinning the old map and renaming the temporary pin to the original path.

## When traffic without disruption is guaranteed

### Safe changes

1. Adding a new map (no changes to existing maps’ properties).

2. Increasing an existing map’s `MaxEntries` (capacity increase) without changing key/value layout or sizes.

### Changes that will break traffic without disruption

1. `Key` type or `Value` type changes, including changes to nested struct definitions.

2. `KeySize` or `ValueSize` changes (e.g. from 4 bytes to 16 bytes).

3. Field offset changes (field reorder, delete, rename) or nested struct layout changes that make the layout incompatible.

4. MapType change (e.g. Hash → Array).

5. Reducing `MaxEntries`.

When any of the above changes are detected, the upgrade logic treats the old map as incompatible and creates a new empty map, which causes runtime state loss.

## Test recommendations

Package your new daemon build into an image and publish it. Set that image address in the environment variable KMESH_UPGRADE_IMAGE. In a fresh clone of the project , run the e2e test while skipping the test’s internal image build step by passing the --skip-build-daemonupgarde-image flag (this flag tells the test to use the externally supplied KMESH_UPGRADE_IMAGE). The TestKmeshUpgrade test will then perform a rolling upgrade of the daemonset and validate whether traffic continuity is preserved.
