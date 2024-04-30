---
title: Kmesh ads mode proposal
authors:
- "@LiZhenCheng9527"
reviewers:
approvers:

creation-date: 2024-04-28

---

## Backgroud

Because Kmesh provides a new data plane architecture, the control plane still uses istiod. So still need `ads`` for Kmesh and Istiod synchronisation.

## Kmesh ads mode Function Design

The process of synchronising Kmesh with istiod is the same as synchronising envoy with istiod:

- **Create grpc links with istiod.**
  After creating the grpc link, use the `streamAggregatedResources`` method to establish a link with istiod.
- **Getting the initial configuration of the cluster.**
  After establishing a link, Kmesh sends a clusterType empty ads message to istiod to get a snapshot of the current cluster configuration resources.
- **Processing DiscoveryResponse response messages received from istiod.**
  This is followed by the processing of the istiod return message. Kmesh processes the response differently depending on the typeUrl in the response.
  CDS updates (if any) must always be pushed first.
  EDS updates (if any) must arrive after CDS updates for the respective clusters. LDS updates must arrive after corresponding CDS/EDS updates.
  RDS updates related to the newly added listeners must arrive after CDS/EDS/LDS updates.
- **Updating req and generating ack after processing.**
  And for each xds processed, the serviceEvent.cache and bpf map are both updated.
- **Send ack to istiod.**
  A new req or ack is generated when the response from istiod is processed and finally sent to the istiod.
- **Cycle 4 to 6 steps.**

Kmesh is synchronised with the istiod control surfaces through the six steps described above. However, there are still areas in which it can be optimised.

## Optimisation of xds response handling

- 1.Replace `StreamAggregatedResources` to `DeltaAggregatedResources`:
  StreamAggregatedResources is a full update, and when a number of pods in the cluster, a lot of configurations are issued. Change it to DeltaAggregatedResources and only incremental updates will be issused for each update, saving bandwidth.
- 2.Asynchronously update `bpf map and` and `serviceEvent.cache`
  At this stage the bpf.map update takes much longer to process than the serviceEvent.cache.
  The serial processing of updating serviceEvent.cache and then updating the bpf map would greatly reduce the efficiency of Kmesh.
  So we should use a parallel update of the bpf map and serviceEvent.cache to optimise the response handling.

  Next, I will describe a programme:
  The refresh time of bpf map is much longer than the refresh time of serviceEvent cache. When bpf map is refreshing, serviceEvent cache continues to process messages from istiod and keeps updating the cache. After each refresh of bpf map finishes, it compares the contents of serviceEvent.cache and the contents refreshed into bpf map. If they are different, it will deep copy the cache and lock at this stage to ensure consistency during deep copying. Then it continues executing the map cache. If they are the same, it ends the bpf map flush until the next update handling. If bpf map flush fails, it will roll back ServiceEvent.Cache to the copy of bpf map refresh to ensure consistency and report an error.

  ```console
  func responseHandling() {
      go service.cache.flush()
      go bpf_map.flush()
  }

  func service.cache.flush() {
      service.cache.update()
  }

  cacheDeepcopy := service.cache.DeepCopy()

  func bpf_map.flush() {
    for {
      if serviceEvent.Cache == cacheDeepCopy {
          break
      } else {
          if err := bpf_map.Update(); err != nil {
              serviceEvent.Cache = cacheDeepcopy
              log
          }
      }
    }
  }
  ```

However, there is a problem with this solution: there is no guarantee that the order in which cds/lds/eds/rds are refreshed in bpf map.
