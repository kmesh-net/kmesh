--- 
title: Circuit Breaking Test Guide
authors:
- "@LiZhenCheng9527 @zrggw"
reviews:
-
approves:
-

create-date: 2025-5-29

---

This document provides a step-by-step guide on how to test the circuit breaking functionality of kmesh. It covers deploying the necessary components, configuring traffic rules, and observing the circuit breaking behavior.

## Step 1. Deploy kmesh

Please read [Quick Start](https://kmesh.net/docs/setup/quick-start) to complete the deployment of kmesh.

## Step 2. Deploy fortio and httpbin

``` sh
kubectl apply -f -<<EOF
apiVersion: v1
kind: Service
metadata:
  name: fortio
  labels:
    app: fortio
    service: fortio
spec:
  ports:
  - port: 8080
    name: http
  selector:
    app: fortio
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fortio-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: fortio
  template:
    metadata:
      annotations:
        # This annotation causes Envoy to serve cluster.outbound statistics via 15000/stats
        # in addition to the stats normally served by Istio. The Circuit Breaking example task
        # gives an example of inspecting Envoy stats via proxy config.
        proxy.istio.io/config: |-
          proxyStatsMatcher:
            inclusionPrefixes:
            - "cluster.outbound"
            - "cluster_manager"
            - "listener_manager"
            - "server"
            - "cluster.xds-grpc"
      labels:
        app: fortio
    spec:
      containers:
      - name: fortio
        image: fortio/fortio:latest_release
        imagePullPolicy: Always
        ports:
        - containerPort: 8080
          name: http-fortio
        - containerPort: 8079
          name: grpc-ping
EOF
```

```sh
kubectl apply -f sample/httpbin/httpbin.yaml
```

## Step 3. Configure waypoint for httpbin

Install Kubernetes Gateway API CRDs before configuring waypoint:

``` sh
kubectl get crd gateways.gateway.networking.k8s.io &> /dev/null || \
  { kubectl kustomize "github.com/kubernetes-sigs/gateway-api/config/crd/experimental?ref=444631bfe06f3bcca5d0eadf1857eac1d369421d" | kubectl apply -f -; }
```

Then, configure waypoint for httpbin:
```sh
kmeshctl waypoint apply -n default --name httpbin-waypoint --image ghcr.io/kmesh-net/waypoint:latest
kubectl label service httpbin istio.io/use-waypoint=httpbin-waypoint
```

## Step 4. Configure destinationRule

```sh
kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata:
  name: httpbin
spec:
  host: httpbin
  trafficPolicy:
    connectionPool:
      tcp:
        # Maximum number of TCP connections to the target service
        maxConnections: 1
      http:
        # Maximum number of pending HTTP requests
        http1MaxPendingRequests: 1
        # Maximum number of requests allowed per connection.
        maxRequestsPerConnection: 1
    outlierDetection:
      # Circuit breaker settings
      consecutive5xxErrors: 1
      interval: 1s
      baseEjectionTime: 3m
      maxEjectionPercent: 100
EOF
```

## Step 5. View the cds configuration in waypoint through istioctl

```sh
istioctl proxy-config all <waypoint-pod-name> # Replace <waypoint-pod-name> with the actual pod name of the waypoint
```

## Step 6. Access through fortio to see the actual phenomenon


```sh
export FORTIO_POD=$(kubectl get pods -l app=fortio -o 'jsonpath={.items[0].metadata.name}')
kubectl exec "$FORTIO_POD" -c fortio -- /usr/bin/fortio load -c 5 -qps 0 -n 50 -loglevel Warning http://httpbin:8000/get
```

You should see some requests failing with 503 errors, indicating that the circuit breaker is functioning as expected.
```sh
...
IP addresses distribution:
10.96.56.163:8000: 33
Code 200 : 19 (38.0 %)
Code 503 : 31 (62.0 %)
Response Header Sizes : count 50 avg 114.38 +/- 146.1 min 0 max 301 sum 5719
Response Body/Total Sizes : count 50 avg 382.48 +/- 46.6 min 346 max 442 sum 19124
All done 50 calls (plus 0 warmup) 3.162 ms avg, 1247.0 qps
```