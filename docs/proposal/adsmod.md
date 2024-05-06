---
title: Kmesh bpf map refresh optimization
authors:
- "@LiZhenCheng9527"
reviewers:
approvers:

creation-date: 2024-04-28

---

## Backgroud

Because Kmesh provides a new data plane architecture, the control plane still uses istiod. So still need `ads`` for Kmesh and Istiod synchronisation.

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
  At this stage the bpf.map update takes much longer to process than the xDS.cache.
  The serial processing of updating xDS.cache and then updating the bpf map would greatly reduce the efficiency of Kmesh.
  So we should use different threads to update bpf.map and xDS.cache.

  When bpf map is refreshing, xDS.cache continues to process messages from istiod and keeps updating the cache. After each refresh of bpf map finishes, it compares the contents of xDS.cache and the contents refreshed into bpf map. If they are different, it will deep copy the cache and lock at this stage to ensure consistency during deep copying. Then it continues executing the map cache. If bpf map flush fails, it will roll back xDS.Cache to the copy of bpf map refresh to ensure consistency and report an error.

  ```console
  func (c *client) Run() {
      ...
      go c.responseHandle()
      go c.bpfMapFlush()
      ...
  }

  func (c *client) responseHandle() {
      ...
      xDS.cache.Update()
  }

  func (c *client) bpfMapFlush() {
    cacheDuplicate := c.Event.xDS.NewCache()
    for {
      if c.Event.xDS.cache == cacheDuplicate {
          time.sleep(interval)
      } else {
          cacheDeepCopy := c.Event.xDS.DeepCopy()
          if err := bpf_map.Update(cacheDeepCopy); err != nil {
              bpf_map.Rollback(cacheDuplicate)
              log
          }
          cacheDuplicate = cacheDeepCopy
      }
    }
  }

  func bpt_map.Update(cache xDS.cache) error {
      // refresh the corresponseding bpf map in the order of cds->lds->eds->rds 
      switch cache.changed {
      case clustercachechanged:
          if err := clusterMap.Update; err != nil {
              return err
          }
      case listenercachechanged:
          if err := listenerMap.Update err != nil {
              return err
          }
      case endpointcachechanged:
          if err := endpointMap.Update err != nil {
              return err
          }
      case Routecachechanged:
          if err := RouteMap.Update err != nil {
              return err
          }
      }
  }
  ```
