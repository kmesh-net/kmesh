---
sidebar_position: 9
title: Locality Load Balancing
---

This document explains how to use Locality Load Balancing with Istio in Kmesh.

Note: Kmesh's current Locality Load Balancing operates at L4 and only supports [Locality Failover](https://istio.io/latest/docs/tasks/traffic-management/locality-load-balancing/failover/).

## What is Locality Load Balancing?

A locality describes the geographic location of a workload instance in the mesh. Locality Load Balancing improves availability and performance by routing traffic based on the location of service instances.

We strongly recommend reading https://istio.io/latest/docs/tasks/traffic-management/locality-load-balancing/ for background on locality load balancing.

## Supported Modes and Configuration Methods for Kmesh

Currently, Istio's ambient mode supports specifying a fixed locality load-balancing policy via configuration. Kmesh supports two modes: PreferClose and Local.

### 1. PreferClose

Failover mode that uses NETWORK, REGION, ZONE, and SUBZONE as the routing preference.

- With `spec.trafficDistribution` (k8s >= beta [1.31.0](https://kubernetes.io/docs/concepts/services-networking/service/), istio >= [1.23.1](https://istio.io/latest/news/releases/1.23.x/announcing-1.23/))

  ```yaml
  spec:
    trafficDistribution: # spec.trafficDistribution
      preferClose: true
  ```

- With annotation

  ```yaml
  metadata:
    annotations:
      networking.istio.io/traffic-distribution: PreferClose
  ```

### 2. Local

Strict mode that restricts traffic to the current node.

- Set `spec.internalTrafficPolicy: Local` (k8s >= beta 1.24 or >= 1.26)

  ```yaml
  spec:
    internalTrafficPolicy: Local
  ```

## Experimental Testing

### Prepare the environment

- Refer to [develop with kind](/docs/setup/develop-with-kind.md).
- A three-node kind cluster is required.
- istio >= 1.23.1
- k8s >= 1.31.0
- Ensure sidecar injection is disabled: `kubectl label namespace default istio-injection-`
- Required images:
  - `docker.io/istio/examples-helloworld-v1`
  - `curlimages/curl`

```yaml
kind create cluster --image=kindest/node:v1.31.0 --config=- <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ambient
nodes:
- role: control-plane
- role: worker
- role: worker
- role: worker
EOF
```

### 1. Assign locality information to nodes

```bash
kubectl label node ambient-worker topology.kubernetes.io/region=region
kubectl label node ambient-worker topology.kubernetes.io/zone=zone1
kubectl label node ambient-worker topology.kubernetes.io/subzone=subzone1
```

```bash
kubectl label node ambient-worker2 topology.kubernetes.io/region=region
kubectl label node ambient-worker2 topology.kubernetes.io/zone=zone1
kubectl label node ambient-worker2 topology.kubernetes.io/subzone=subzone2
```

```bash
kubectl label node ambient-worker3 topology.kubernetes.io/region=region
kubectl label node ambient-worker3 topology.kubernetes.io/zone=zone2
kubectl label node ambient-worker3 topology.kubernetes.io/subzone=subzone3
```

### 2. Start test servers

- Create the `sample` namespace:

  ```bash
  kubectl create namespace sample
  ```

- Create the service:

  ```bash
  kubectl apply -n sample -f - <<EOF
  apiVersion: v1
  kind: Service
  metadata:
    name: helloworld
    labels:
      app: helloworld
      service: helloworld
  spec:
    ports:
    - port: 5000
      name: http
    selector:
      app: helloworld
    trafficDistribution: PreferClose
  EOF
  ```

- Start a service instance on `ambient-worker`:

  ```yaml
  kubectl apply -n sample -f - <<EOF
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: helloworld-region.zone1.subzone1
    labels:
      app: helloworld
      version: region.zone1.subzone1
  spec:
    replicas: 1
    selector:
      matchLabels:
        app: helloworld
        version: region.zone1.subzone1
    template:
      metadata:
        labels:
          app: helloworld
          version: region.zone1.subzone1
      spec:
        containers:
        - name: helloworld
          env:
          - name: SERVICE_VERSION
            value: region.zone1.subzone1
          image: docker.io/istio/examples-helloworld-v1
          resources:
            requests:
              cpu: "100m"
          imagePullPolicy: IfNotPresent
          ports:
          - containerPort: 5000
        nodeSelector:
          kubernetes.io/hostname: ambient-worker
  EOF
  ```

- Start a service instance on the ambient-worker2

  ```yaml
  kubectl apply -n sample -f - <<EOF
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: helloworld-region.zone1.subzone2
    labels:
      app: helloworld
      version: region.zone1.subzone2
  spec:
    replicas: 1
    selector:
      matchLabels:
        app: helloworld
        version: region.zone1.subzone2
    template:
      metadata:
        labels:
          app: helloworld
          version: region.zone1.subzone2
      spec:
        containers:
        - name: helloworld
          env:
          - name: SERVICE_VERSION
            value: region.zone1.subzone2
          image: docker.io/istio/examples-helloworld-v1
          resources:
            requests:
              cpu: "100m"
          imagePullPolicy: IfNotPresent
          ports:
          - containerPort: 5000
        nodeSelector:
          kubernetes.io/hostname: ambient-worker2
  EOF
  ```

- Start a service instance on the ambient-worker3

  ```yaml
  kubectl apply -n sample -f - <<EOF
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: helloworld-region.zone2.subzone3
    labels:
      app: helloworld
      version: region.zone2.subzone3
  spec:
    replicas: 1
    selector:
      matchLabels:
        app: helloworld
        version: region.zone2.subzone3
    template:
      metadata:
        labels:
          app: helloworld
          version: region.zone2.subzone3
      spec:
        containers:
        - name: helloworld
          env:
          - name: SERVICE_VERSION
            value: region.zone2.subzone3
          image: docker.io/istio/examples-helloworld-v1
          resources:
            requests:
              cpu: "100m"
          imagePullPolicy: IfNotPresent
          ports:
          - containerPort: 5000
        nodeSelector:
          kubernetes.io/hostname: ambient-worker3
  EOF
  ```

### 3. Test from a client pod

- Start the test client on `ambient-worker`:

  ```bash
  kubectl apply -n sample -f - <<EOF
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: sleep
  spec:
    replicas: 1
    selector:
      matchLabels:
        app: sleep
    template:
      metadata:
        labels:
          app: sleep
      spec:
        terminationGracePeriodSeconds: 0
        containers:
        - name: sleep
          image: curlimages/curl
          command: ["/bin/sleep", "infinity"]
          imagePullPolicy: IfNotPresent
          volumeMounts:
          - mountPath: /etc/sleep/tls
            name: secret-volume
        volumes:
        - name: secret-volume
          secret:
            secretName: sleep-secret
            optional: true
        nodeSelector:
          kubernetes.io/hostname: ambient-worker
  EOF
  ```

- Verify access from the client:

  ```bash
  kubectl exec -n sample "$(kubectl get pod -n sample -l app=sleep -o jsonpath='{.items[0].metadata.name}')" -c sleep -- curl -sSL "http://helloworld:5000/hello"
  ```

  The response should come from the local instance running on `ambient-worker`, for example:

  ```text
  Hello version: region.zone1.subzone1, instance: helloworld-region.zone1.subzone1-6d6fdfd856-9dhv8
  ```

- Remove the local deployment to test failover:

  ```bash
  kubectl delete deployment -n sample helloworld-region.zone1.subzone1
  ```

  Re-run the client request:

  ```bash
  kubectl exec -n sample "$(kubectl get pod -n sample -l app=sleep -o jsonpath='{.items[0].metadata.name}')" -c sleep -- curl -sSL "http://helloworld:5000/hello"
  ```

  The response should now come from the next available locality (example):

  ```text
  Hello version: region.zone1.subzone2, instance: helloworld-region.zone1.subzone2-948c95bdb-7p6zb
  ```

- Relabel `ambient-worker3` to match `ambient-worker2` and redeploy the third instance:

  ```bash
  kubectl label node ambient-worker3 topology.kubernetes.io/zone=zone1 --overwrite
  kubectl label node ambient-worker3 topology.kubernetes.io/subzone=subzone2 --overwrite
  ```

  ```bash
  kubectl delete deployment -n sample helloworld-region.zone2.subzone3

  kubectl apply -n sample -f - <<EOF
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: helloworld-region.zone1.subzone2-worker3
    labels:
      app: helloworld
      version: region.zone1.subzone2-worker3
  spec:
    replicas: 1
    selector:
      matchLabels:
        app: helloworld
        version: region.zone1.subzone2-worker3
    template:
      metadata:
        labels:
          app: helloworld
          version: region.zone1.subzone2-worker3
      spec:
        containers:
        - name: helloworld
          env:
          - name: SERVICE_VERSION
            value: region.zone1.subzone2-worker3
          image: docker.io/istio/examples-helloworld-v1
          resources:
            requests:
              cpu: "100m"
          imagePullPolicy: IfNotPresent
          ports:
          - containerPort: 5000
        nodeSelector:
          kubernetes.io/hostname: ambient-worker3
  EOF
  ```

  Test multiple times from the client:

  ```bash
  kubectl exec -n sample "$(kubectl get pod -n sample -l app=sleep -o jsonpath='{.items[0].metadata.name}')" -c sleep -- curl -sSL "http://helloworld:5000/hello"
  ```

  Responses will alternate between the two instances in the same locality, for example:

  ```text
  Hello version: region.zone1.subzone2-worker3, instance: helloworld-region.zone1.subzone2-worker3-6d6fdfd856-6kd2s
  Hello version: region.zone1.subzone2, instance: helloworld-region.zone1.subzone2-948c95bdb-7p6zb
  ```
