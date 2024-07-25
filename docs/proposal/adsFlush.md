---
title: Kmesh bpf map refresh optimization
authors:
- "@LiZhenCheng9527"
reviewers:
approvers:

creation-date: 2024-04-28

---

## Backgroud

Because Kmesh provides a new data plane architecture, the control plane still uses istiod. So still need `ads` for Kmesh and Istiod synchronisation.

## Kmesh xDS Mode Function Design

The process of synchronising Kmesh with istiod is the same as synchronising envoy with istiod:

- **Create grpc links with istiod.**
  After creating the grpc link, use the `streamAggregatedResources`` method to establish a link with istiod.
- **Send an initial CDS subscription request to istiod.**
  After establishing a link, Kmesh sends an initial CDS subscription request to for control plane clustering information.
- **Processing DiscoveryResponse response messages received from istiod.**
  In general, to avoid traffic drop, sequencing of updates should follow a make before break model, wherein:
  - CDS updates (if any) must always be pushed first.
  - EDS updates (if any) must arrive after CDS updates for the respective clusters. LDS updates must arrive after corresponding CDS/EDS updates.
  - LDS updates must arrive after corresponding CDS/EDS updates.
  - RDS updates related to the newly added listeners must arrive after CDS/EDS/LDS updates.
- **Updating response and generating ack.**
  And for each xds processed, the xDS.cache and bpf map are both updated.
- **Send ack to istiod.**
  A new req or ack is generated when the response from istiod is processed and finally sent to the istiod.
- **Cycle 4 to 6 steps.**

Kmesh is synchronised with the istiod control surfaces through the six steps described above. However, there are still areas in which it can be optimised.

## Optimisation of xds response handling

- Asynchronously update `bpf map` and `xDS.cache`:
  At this stage the bpf.map update takes longer to process than the xDS.cache.
  The serial processing of updating xDS.cache and then updating the bpf map would greatly reduce the efficiency of Kmesh.
  So we should update the `bpf map` asynchronously to improve efficiency of Kmesh.

  When the bpf map is being updated, the xDS controller will continue processing configuration update messages from Istiod and update `xDS.Cache`. After each bpf map update is completed, it will check `xDS.Cache` through a global variable to see if it has been changed. If changed, it will make a deep copy of `xDS.Cache` and continue updating the bpf map.

<div align="center">
<img src="pics/map_flush.svg" width="800" />
</div>

As shown above, the Ads Controller continues to update the `xDS.Cache` at the time of the bpf map update.

When the map flush controller starts a new processing, it first checks `xDS.cache` through a global variable to see if it has changed. The `map flush controller` is awakened by cond(A conditional variable in golang). The ads controller, after updating, will set the global variable change to true, and use cond to awaken the map flush controller waiting. If it has changed, it will make a deep copy of `xDS.Cache`.

Then update the bpf map based on `cache Deepcopy`. The Map Flush Controller maintains a copy of the previous cds, eds, lds, and rds configurations. When it receives an updated xDS configuration, it compares the new cds, rds, lds, and eds configurations against the stored previous versions. Based on the comparison results, the Map Flush Controller identifies any differences between the new and previous configurations. It then performs an incremental update of the BPF map by only updating the entries that changed, as indicated by the diff analysis.

- Adding new configuration resources.
- Removing deleted resources.
- Modifying updated resources.

This allows the Map Flush Controller to optimize the BPF map update process by avoiding a full re-write and instead focusing the update on just the modified configuration resources. After successfully updating the bpf map, update the cds, eds, lds, and rds configurations in Map Flush Controller.

If the update fails, Map Flush Controller will do a retry. And logs the error in the logs. The xDS Controller sends a Nack to istiod to inform that there is an error in the bpf map update of Kmesh.

If the `xDS.Cache` is the same as the `map Cache`, the update will not be triggered. Until an update to xDS.Cache occurs, the `bpf map` begins update.
