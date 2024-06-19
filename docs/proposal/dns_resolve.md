---
title: Your short, descriptive title
authors:
- "@zhxuzhonghu"
reviewers:
- 
approvers:
- 


creation-date: 2024-05-08

---

## Support DNS Resolution in Cluster Manager

<!--
This is the title of your KEP. Keep it short, simple, and descriptive. A good
title can help communicate what the KEP is and should be considered as part of
any review.
-->

### Summary

<!--
This section is incredibly important for producing high-quality, user-focused
documentation such as release notes or a development roadmap.
A good summary is probably at least a paragraph in length.
-->

Envoy supports many different cluster types, including `Strict DNS`, `Logical DNS`. However, given to Kmesh works in the kernel with ebpf. Previously Kmesh does not either of the DNS typed clusters. For traffic matches these kind of cluster, it will be dropped. 

In this propsosal, I would suggest to improve Kmesh to support DNS typed cluster, so we can support all kinds of clusters afterwards.


### Motivation

<!--
This section is for explicitly listing the motivation, goals, and non-goals of
this KEP.  Describe why the change is important and the benefits to users.
-->

In istio, [External Name service](https://kubernetes.io/docs/concepts/services-networking/service/#externalname) and DNS resolution typed [ServiceEntry](https://istio.io/latest/docs/reference/config/networking/service-entry/#ServiceEntry-Resolution) are widely used. For both kind of configs, istiod will generate associated DNS typed clusters.

So many people have depend on this kind services, Kmesh have to support it to make people migrate to it seamlessly.

Suppose we create a ServiceEntry like below:

```yaml
apiVersion: networking.istio.io/v1
kind: ServiceEntry
metadata:
  name: se
  namespace: default
spec:
  hosts:
  - news.google.com
  ports:
  - name: port1
    number: 80
    protocol: HTTP
  resolution: DNS
```

It will result into a cluster below:

```json
{
    "name": "outbound|80||news.google.com",
    "type": "STRICT_DNS",
    "connectTimeout": "10s",
    "lbPolicy": "LEAST_REQUEST",
    "loadAssignment": {
        "clusterName": "outbound|80||news.google.com",
        "endpoints": [
            {
                "locality": {},
                "lbEndpoints": [
                    {
                        "endpoint": {
                            "address": {
                                "socketAddress": {
                                    "address": "news.google.com",
                                    "portValue": 80
                                }
                            }
                        },
                        "metadata": {
                            "filterMetadata": {
                                "istio": {
                                    "workload": ";;;;"
                                }
                            }
                        },
                        "loadBalancingWeight": 1
                    }
                ],
                "loadBalancingWeight": 1
            }
        ]
    },
    "dnsRefreshRate": "60s",
    "respectDnsTtl": true,
    "dnsLookupFamily": "V4_ONLY",
    "commonLbConfig": {
        "localityWeightedLbConfig": {}
    },
    ...
}
```


#### Goals

<!--
List the specific goals of the KEP. What is it trying to achieve? How will we
know that this has succeeded?
-->

Now it is very clear, we want to:

- Support dns resolution typed services management, a workload can access DNS services.



#### Non-Goals

<!--
What is out of scope for this KEP? Listing non-goals helps to focus discussion
and make progress.
-->

- Donot capture application dns resolution requests.

- Donot provide node local dns service for application, at least this is not the goal of this proposal. 

- Since istiod doesnot support workload dns resolution, Kmesh does not support it in workload mode either.


### Proposal

<!--
This is where we get down to the specifics of what the proposal actually is.
This should have enough detail that reviewers can understand exactly what
you're proposing, but should not include things like API designs or
implementation. What is the desired outcome and how do we measure success?.
The "Design Details" section below is for the real
nitty-gritty.
-->

We should implement a new component to do dns resolve, called `dns resolver`. It should basically do:

- DNS resolve for endpoints within DNS typed clusters

- Record the results in the dns name table

- Periodically refresh the dns name table respecting `dnsRefreshRate` or dns ttl.

We should also provide a way to let the ebpf cluster manager prog access the dns name table.


### Design Details

<!--
This section should contain enough information that the specifics of your
change are understandable. This may include API specs (though not always
required) or even code snippets. If there's any ambiguity about HOW your
proposal will be implemented, this is the place to discuss them.
-->

In theory, we can think of implementing dns resolver either in kernel or userspace. Considering the complexity, I suggest we do that in Kmesh daemon.

![DNS Resolver Arch](./pics/dns-resolver.svg)

`DNS Resolver` works in ads mode, so it is run only when ads is enabled. It collaborates with ads controller, and the whole workflow is :

- ads controller is responsible of subscribing the xDS from istiod, when it receives a cluster with dns type, it notifies the `DNS Resolver` via a channel.

- `DNS Resolver` is responsible of resolving the dns domain with the dns configuration within Kmesh daemon.

- After resolved, `DNS Resolver` will set the name table via updating the bpf hash map.

- It is important but not depicted in the graph, `DNS Resolver` should refresh the dns address periodically by respecting the `dnsRefreshRate` and ttl, which one is shorter.


As to the dns resolution, package `github.com/miekg/dns` provide good libs that can be used to do no matter dns resolve or dns serving. Though it is not the target to support dns serving here, we should choose a package that do have such capabilities, so that we can extend it to do in the future. Another reason why suggest using this package is that, coredns also make use of it, so it is widely used in production.

We should make sure no dns name can be leaked. It is very common a cluster can be removed following a service deletion. Now in Kmesh we use Stow xDS, each time it receives CDS response it would include all clusters within the mesh. And ads controller parses them, respond and then store them in user space cache and bpf maps. We can make ads controller do `Stow` notification too. To be more clearly, when ads controller parses all the clusters, it should send all the dns domains that need to be resolved to `DNS Resolver`.

Since the notification is by golang channel, it is vety efficient, `Stow` should be good to go. In `DNS Resolver`, it should create a map to record all the dns domains it need to resolve. So every notification it should be able to distinguish new added, deleted and unchanged dns domains.

For new added ones, it should resolve them immediately and write the result to dns name table, at last push them into the refresher queue. For the deleted ones, it should remove them from local cache and the periodical refresher queue. And for unchanged ones, it can do nothing.


#### Test Plan

<!--
**Note:** *Not required until targeted at a release.*
Consider the following in developing a test plan for this enhancement:
- Will there be e2e and integration tests, in addition to unit tests?
- How will it be tested in isolation vs with other components?
No need to outline all test cases, just the general strategy. Anything
that would count as tricky in the implementation, and anything particularly
challenging to test, should be called out.
-->

### Alternatives

<!--
What other approaches did you consider, and why did you rule them out? These do
not need to be as detailed as the proposal, but should include enough
information to express the idea and why it was not acceptable.
-->

<!--
Note: This is a simplified version of kubernetes enhancement proposal template.
https://github.com/kubernetes/enhancements/tree/3317d4cb548c396a430d1c1ac6625226018adf6a/keps/NNNN-kep-template
-->