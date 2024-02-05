# xDS Response Handling in Kmesh

Kmesh now makes use of StoW ADS to subscribe xDS resources from xDS control plane. Basically, there are four types of xDS subscribed， including CDS, EDS, LDS, RDS
We are going to make use of incremental ADS to subscribe `Address` resources, which is introduced from ambient mesh.

The goal is to design a better xDS cache to suit for both StoW and Incremental ADS modes.

## How we subscribe xDS resources

Kmesh daemon initialize an ADS client, and subscribes to xDS resources spontaneously. For each kind of resources, we registered an associated resource handler.
We heavily rely on the resource handler to update xDS cache, maintain bpf map and ACK to control plane. It behaves similar to many other xds client.

![](./pics/xds.svg)

## Cache status maintain

Keep in mind we have two levels of cache, one reside in userspace, which is read and write by ads loader.
The other one is bpf map, which is read by ebpf code, and write by ads loader. So ads loader needs to know which resource is new added, which is unchanged, and which is removed.
In order to make kmesh cache suit for both StoW and Delta xDS, first let us understand the requirements.


### StoW

StoW ADS returns all xDS resources, in the xds handler we need to compare the responses with the user space xDS cache to know the new added, deleted, unchanged sets of resources.

### Delta

Delta xDS returns updated and removed resources, the difference with StoW is that removed resource are explicitly set in [DeltaDiscoveryResponse.RemovedResources](https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/discovery/v3/discovery.proto#envoy-v3-api-msg-service-discovery-v3-deltadiscoveryresponse).

![](./pics/xds_cache.svg)

Detailed workflow is shown in the diagram:
1. After xDS handler receives the responses, the ads loader will compare with the xDS cache to classify resources into three sets, Removed/Updated/Unchanged.
2. Store the Updated resources in the xDS cache with status `ApiStatus_UPDATE`
3. Update the api status of the removed resources to `ApiStatus_DELETE`
4. Flush the resources to bpf map. Delete the resource if the api status is `ApiStatus_DELETE`, and update the resource if the api status is `ApiStatus_UPDATE`. And then reset the api status from `ApiStatus_UPDATE` to `ApiStatus_NONE`.
5. Delete resources marked `ApiStatus_DELETE` from the user space xDS cache



