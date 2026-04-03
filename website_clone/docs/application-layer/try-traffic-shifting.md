---
sidebar_position: 5
title: Try Traffic Shifting
---

## Preparation

1. Make default namespace managed by Kmesh
2. Deploy bookinfo as sample application and sleep as curl client
3. Install service granularity waypoint for reviews service

_The above steps could refer to [Install Waypoint | Kmesh](/docs/application-layer/install_waypoint.md#preparation)_

## Apply weight-based routing

Configure traffic routing to send 90% of requests to `reviews v1` and 10% to `reviews v2`:

```bash
[root@ ~]# kubectl apply -f -<<EOF
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: reviews
spec:
  hosts:
    - reviews
  http:
  - route:
    - destination:
        host: reviews
        subset: v1
      weight: 90
    - destination:
        host: reviews
        subset: v2
      weight: 10
---
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: reviews
spec:
  host: reviews
  trafficPolicy:
    loadBalancer:
      simple: RANDOM
  subsets:
  - name: v1
    labels:
      version: v1
  - name: v2
    labels:
      version: v2
  - name: v3
    labels:
      version: v3
EOF
```

Confirm that roughly 90% of the traffic go to `reviews v1`

```bash
[root@ ~]# kubectl exec deploy/sleep -- sh -c "for i in \$(seq 1 100); do curl -s http://productpage:9080/productpage | grep reviews-v.-; done"
        <u>reviews-v1-57c85f47fb-n9llm</u>
        <u>reviews-v1-57c85f47fb-n9llm</u>
        <u>reviews-v1-57c85f47fb-n9llm</u>
        <u>reviews-v2-64776cb9bd-grnd2</u>
        <u>reviews-v1-57c85f47fb-n9llm</u>
        <u>reviews-v1-57c85f47fb-n9llm</u>
        ...
        <u>reviews-v1-57c85f47fb-n9llm</u>
        <u>reviews-v1-57c85f47fb-n9llm</u>
        <u>reviews-v2-64776cb9bd-grnd2</u>
        <u>reviews-v1-57c85f47fb-n9llm</u>
        <u>reviews-v1-57c85f47fb-n9llm</u>
        <u>reviews-v2-64776cb9bd-grnd2</u>
```

## Understanding what happened

Because `default` namespace has been managed by Kmesh and we have deployed a waypoint proxy for service `bookinfo-reviews`, so all traffic sent to service `reviews` will be forwarded to waypoint by Kmesh. Waypoint will send 90% of requests to `reviews v1` and 10% to `reviews v2` according to the route rules we set.

## Cleanup

1. Remove the application routing rules:

```bash
kubectl delete virtualservice reviews
kubectl delete destinationrules reviews
```

2. If you are not planning to explore any follow-on tasks, refer to the [Install Waypoint/Cleanup](/docs/application-layer/install_waypoint.md#cleanup) instructions to remove waypoint and shutdown the application.

## Demo

<div className="video-responsive">
  <iframe
    src="https://www.youtube.com/embed/qX6qFfk4Z4k"
    frameborder="0"
    allowfullscreen
  ></iframe>
</div>
