---
sidebar_position: 3
title: Install Waypoint
---

If you want to make use of Kmesh L7 features, this is the prerequisites to install waypoint.

## Preparation

1. Install Kmesh:

   Please refer [quickstart](/docs/setup/quick-start.md)

2. Deploy sample application:

   Using Kmesh manage default namespace

   ```bash
   [root@ ~]# kubectl label namespace default istio.io/dataplane-mode=Kmesh
   [root@ ~]# kubectl get namespace -L istio.io/dataplane-mode
   NAME                 STATUS   AGE   DATAPLANE-MODE
   default              Active   13d   Kmesh
   istio-system         Active   13d   
   kmesh-system         Active   27h   
   kube-node-lease      Active   13d   
   kube-public          Active   13d   
   kube-system          Active   13d   
   local-path-storage   Active   13d   
   ```

3. Deploy bookinfo:

   ```bash
   [root@ ~]# kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.21/samples/bookinfo/platform/kube/bookinfo.yaml
   ```

4. Deploy sleep as curl client:

   ```bash
   [root@ ~]# kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.21/samples/sleep/sleep.yaml
   [root@ ~]# kubectl get pods
   NAME                             READY   STATUS    RESTARTS   AGE
   details-v1-5f4d584748-bz42z      1/1     Running   0          72s
   productpage-v1-564d4686f-2rjqc   1/1     Running   0          72s
   ratings-v1-686ccfb5d8-dnzkf      1/1     Running   0          72s
   reviews-v1-86896b7648-fqm4z      1/1     Running   0          72s
   reviews-v2-b7dcd98fb-nn42q       1/1     Running   0          72s
   reviews-v3-5c5cc7b6d-q4r5h       1/1     Running   0          72s
   sleep-9454cc476-86vgb            1/1     Running   0          62s
   ```

5. Test bookinfo works as expected:

   ```bash
   [root@ ~]# kubectl exec deploy/sleep -- curl -s http://productpage:9080/ | grep -o "<title>.*</title>"
   <title>Simple Bookstore App</title>
   ```

## Install waypoint

Waypoints can be used at three granularity: namespace, service and pod. And you could also install multiple waypoints at different granularity within a namespace.
Below we will learn how to deploy different waypoints for different granularity. We can use `kmeshctl waypoint` subcommands to generate or apply waypoint.

To enable a namespace, service or pod to use a waypoint, add the `istio.io/use-waypoint` label with a value of the waypoint name.
We can also specify a customized waypoint image with `--image`, by default this default to `ghcr.io/kmesh-net/waypoint:{VERSION}`

### Configure a waypoint for a specific service

Deploy a waypoint `reviews-svc-waypoint` for service `reviews`, so any traffic to `reviews` from a client managed by Kmesh will be mediated by the waypoint proxy

```bash
[root@ ~]# kmeshctl waypoint apply --for service -n default --name=reviews-svc-waypoint

waypoint default/reviews-svc-waypoint applied
```

Label the `reviews` service to use `reviews-svc-waypoint` waypoint:

```bash
[root@ ~]# $ kubectl label service reviews istio.io/use-waypoint=reviews-svc-waypoint

service/reviews labeled
```

After the waypoint is up and running, Kmesh L7 is enabled!

```bash
[root@ ~]# kubectl get pods
NAME                                      READY   STATUS    RESTARTS   AGE
details-v1-cdd874bc9-xcdnj                1/1     Running   0          30m
productpage-v1-5bb9985d4d-z8cws           1/1     Running   0          30m
ratings-v1-6484d64bbc-pkv6h               1/1     Running   0          30m
reviews-svc-waypoint-8cb4bdbf-9d5mj       1/1     Running   0          30m
reviews-v1-598f9b58fc-2rw7r               1/1     Running   0          30m
reviews-v2-5979c6fc9c-72bst               1/1     Running   0          30m
reviews-v3-7bbb5b9cf7-952d8               1/1     Running   0          30m
sleep-5577c64d7c-n7rxp                    1/1     Running   0          30m
```

### Configure waypoint for a specific namespace

Deploy a waypoint for the `default` namespace with default name `waypoint`. By specifying `--enroll-namespace`, the namespace will be labeled with `istio.io/use-waypoint=waypoint`

```bash
[root@ ~]# kmeshctl waypoint apply -n default --enroll-namespace
waypoint default/waypoint applied
namespace default labels with "istio.io/use-waypoint: waypoint"
```

### Configure waypoint for a specific pod

Deploy a waypoint called reviews-v2-pod-waypoint for the `reviews-v2-5979c6fc9c-72bst` pod.

```bash
[root@ ~]# kmeshctl waypoint apply -n default --name reviews-v2-pod-waypoint --for workload
waypoint default/reviews-v2-pod-waypoint applied
# Label the `reviews-v2` pod to use `reviews-v2-pod-waypoint` waypoint.
[root@ ~]# kubectl label pod reviews-v2-5979c6fc9c-72bst istio.io/use-waypoint=reviews-v2-pod-waypoint
pod/reviews-v2-5b667bcbf8-spnnh labeled
```

Now any requests from pods in the Kmesh to the `reviews-v2` pod IP will be routed through `reviews-v2-pod-waypoint` waypoint for L7 processing and policy enforcement.

## Cleanup

If you are **not** planning to explore any follow-on tasks, go on with the cleanup steps

1. Remove waypoint:

   ### Remove waypoint for service

   ```bash
   [root@ ~]# kmeshctl waypoint delete reviews-svc-waypoint
   [root@ ~]# kubectl label service reviews istio.io/use-waypoint-
   ```

   ### Remove waypoint for namespace

   ```bash
   [root@ ~]# kmeshctl waypoint delete waypoint
   [root@ ~]# kubectl label namespace default istio.io/use-waypoint-
   ```

   ### Remove waypoint for pod

   ```bash
   [root@ ~]# kmeshctl waypoint delete reviews-v2-pod-waypoint
   [root@ ~]# kubectl label pod -l version=v2,app=reviews istio.io/use-waypoint-
   ```

2. Remove sample applications:

   ```bash
   [root@ ~]# kubectl delete -f https://raw.githubusercontent.com/istio/istio/release-1.21/samples/bookinfo/platform/kube/bookinfo.yaml
   [root@ ~]# kubectl delete -f https://raw.githubusercontent.com/istio/istio/release-1.21/samples/sleep/sleep.yaml
   ```

3. Remove default namespace from Kmesh:

   ```bash
   [root@ ~]# kubectl label namespace default istio.io/dataplane-mode-
   ```

## Demo

<div className="video-responsive">
  <iframe
    src="https://www.youtube.com/embed/_mnPQU5SSFo"
    frameborder="0"
    allowfullscreen
  ></iframe>
</div>
