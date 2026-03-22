--- 
title: Rate Limit
sidebar_position: 11
---

This document provides a step-by-step guide on how to test the local rate limit and global rate limit functionality of kmesh. It covers deploying the necessary components, configuring traffic rules, and observing the rate limit behavior.

## Local Rate Limit

### 1. Deploy Kmesh and istiod (version 1.24 or later)

Please read [Quick Start](https://kmesh.net/docs/setup/quick-start) to complete the deployment of kmesh.

### 2. Deploy sleep and httpbin

We will deploy `httpbin` as the backend service for receiving requests and `sleep` as the client for sending requests.

``` sh
kubectl apply -f samples/sleep/sleep.yaml
kubectl apply -f samples/httpbin/httpbin.yaml
```

### 3. Deploy waypoint for httpbin

First, if you haven't installed the Kubernetes Gateway API CRDs, run the following command to install.

``` sh
kubectl get crd gateways.gateway.networking.k8s.io &> /dev/null || \
  { kubectl kustomize "github.com/kubernetes-sigs/gateway-api/config/crd/experimental?ref=v1.4.0" | kubectl create -f -; }
```

Next, create a dedicated Waypoint proxy for the `httpbin` service and label the service to direct its traffic through this Waypoint.

```sh
kmeshctl waypoint apply -n default --name httpbin-waypoint --image ghcr.io/kmesh-net/waypoint:latest

kubectl label service httpbin istio.io/use-waypoint=httpbin-waypoint
```

### 4. Deploy envoyFilter

This `EnvoyFilter` resource injects a local rate-limit filter into the `httpbin` service's Waypoint proxy. The filter is configured with the following rules:

- A request with the header `quota: low` will be limited to **1 request per 300 seconds**.
- A request with the header `quota: medium` will be limited to **3 requests per 300 seconds**.
- Other requests will be subject to a default limit of **10 requests per 300 seconds**.

The `workloadSelector` ensures that this filter is applied only to the `httpbin-waypoint` proxy.

```sh
kubectl apply -f -<<EOF
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: httpbin.ratelimit
  namespace: default
spec:
  configPatches:
  - applyTo: HTTP_FILTER
    match:
      context: SIDECAR_INBOUND
      listener:
        filterChain:
          filter:
            name: envoy.filters.network.http_connection_manager
            subFilter:
              name: envoy.filters.http.router
      proxy:
        proxyVersion: ^1.*
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.filters.http.local_ratelimit
        typed_config:
          '@type': type.googleapis.com/udpa.type.v1.TypedStruct
          type_url: type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
          value:
            customResponseBody: local_rate_limited
            statPrefix: http_local_rate_limiter
  - applyTo: HTTP_ROUTE
    match:
      proxy:
        proxyVersion: ^1.*
      routeConfiguration:
        vhost:
          name: inbound|http|8000
          route:
            name: default
    patch:
      operation: MERGE
      value:
        typed_per_filter_config:
          envoy.filters.http.local_ratelimit:
            '@type': type.googleapis.com/udpa.type.v1.TypedStruct
            type_url: type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
            value:
              customResponseBody: local_rate_limited
              descriptors:
              - entries:
                - key: header_match
                  value: Service[httpbin.default]-User[none]-Id[3100861967]
                tokenBucket:
                  fillInterval: 300s
                  maxTokens: 1
                  tokensPerFill: 1
              - entries:
                - key: header_match
                  value: Service[httpbin.default]-User[none]-Id[4123289408]
                tokenBucket:
                  fillInterval: 300s
                  maxTokens: 3
                  tokensPerFill: 3
              filterEnabled:
                defaultValue:
                  numerator: 100
                runtimeKey: local_rate_limit_enabled
              filterEnforced:
                defaultValue:
                  numerator: 100
                runtimeKey: local_rate_limit_enforced
              rateLimits:
              - actions:
                - headerValueMatch:
                    descriptorValue: Service[httpbin.default]-User[none]-Id[3100861967]
                    headers:
                    - exactMatch: low
                      name: quota
              - actions:
                - headerValueMatch:
                    descriptorValue: Service[httpbin.default]-User[none]-Id[4123289408]
                    headers:
                    - exactMatch: medium
                      name: quota
              responseHeadersToAdd:
              - append: false
                header:
                  key: x-local-rate-limit
                  value: "true"
              statPrefix: http_local_rate_limiter
              tokenBucket:
                fillInterval: 300s
                maxTokens: 10
                tokensPerFill: 10
  workloadSelector:
    labels:
      gateway.networking.k8s.io/gateway-name: httpbin-waypoint
EOF
```

### 5. View the envoy filter configuration in waypoint through istioctl

To verify the configuration, first get the name of the Waypoint pod, then use `istioctl` to inspect its configuration.

```sh
export WAYPOINT_POD=$(kubectl get pod -l gateway.networking.k8s.io/gateway-name=httpbin-waypoint -o jsonpath='{.items[0].metadata.name}')
istioctl proxy-config all $WAYPOINT_POD -ojson | grep ratelimit -A 20
```

### 6. Find the following results, which means the configuration has been sent to waypoint

```sh
        "envoy.filters.http.local_ratelimit": {
            "@type": "type.googleapis.com/udpa.type.v1.TypedStruct",
            "type_url": "type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit",
            "value": {
             "stat_prefix": "http_local_rate_limiter",
             "token_bucket": {
              "max_tokens": 10,
              "tokens_per_fill": 10,
              "fill_interval": "300s"
             },
             "filter_enabled": {
              "default_value": {
               "numerator": 100
              },
              "runtime_key": "local_rate_limit_enabled"
             },
             "filter_enforced": {
              "default_value": {
               "numerator": 100
              },
              "runtime_key": "local_rate_limit_enforced"
             },
             "response_headers_to_add": [
```

### 7. Access httpbin through sleep to see if the rate limit is working

Now, let's send requests from the `sleep` pod to the `httpbin` service to test the rate limit rules.

First, get the name of the `sleep` pod:

```sh
export SLEEP_POD=$(kubectl get pod -l app=sleep -o jsonpath='{.items[0].metadata.name}')
```

#### Test Case 1: "medium" quota

The rule for `quota: medium` allows 3 requests. The fourth request should be rate-limited.

```sh
kubectl exec -it $SLEEP_POD -- curl -H 'quota:medium' http://httpbin:8000/headers
kubectl exec -it $SLEEP_POD -- curl -H 'quota:medium' http://httpbin:8000/headers
kubectl exec -it $SLEEP_POD -- curl -H 'quota:medium' http://httpbin:8000/headers
kubectl exec -it $SLEEP_POD -- curl -H 'quota:medium' http://httpbin:8000/headers
```

Expected output for the fourth command:

``` sh
local_rate_limited
```

#### Test Case 2: "low" quota

The rule for `quota: low` allows only 1 request. The second request should be rate-limited.

```sh
kubectl exec -it $SLEEP_POD -- curl -H 'quota:low' http://httpbin:8000/headers
kubectl exec -it $SLEEP_POD -- curl -H 'quota:low' http://httpbin:8000/headers
```

Expected output for the second command:

``` sh
local_rate_limited
```

## Global Rate Limit

This section shows how to use global rate limit service. You'll deploy a sample app, configure rate limit rules, enable the Envoy HTTP Rate Limit filter on the ingress gateway, and verify responses when limits are exceeded.

### 1. Deploy Kmesh and istiod (version 1.24 to 1.26)

Please read [Quick Start](https://kmesh.net/docs/setup/quick-start) to complete the deployment of kmesh.

### 2. Deploy httpbin

Deploy the httpbin application. Change `replicas: 1` to `replicas: 2` in `./samples/httpbin/httpbin.yaml` to ensure multiple instances handle requests.

``` yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: httpbin
spec:
  replicas: 2
# ...
```

``` sh
kubectl apply -f ./samples/httpbin/httpbin.yaml
```

Create a waypoint for the httpbin service. If you haven't installed the Kubernetes Gateway API CRDs, run the same command in [local rate limit](#3-deploy-waypoint-for-httpbin).

``` sh
kmeshctl waypoint apply -n default --name httpbin-waypoint --image ghcr.io/kmesh-net/waypoint:latest
kubectl label service httpbin istio.io/use-waypoint=httpbin-waypoint
```

### 3. Configure request rate limits

Create a `ConfigMap` consumed by the rate limit service. It defines PATH-based descriptors that limit `/status/200` to 1 request/min, and all other paths to 100 requests/min.

```sh
kubectl apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: ratelimit-config
data:
  config.yaml: |
    domain: ratelimit
    descriptors:
      - key: PATH
        value: "/status/200"
        rate_limit:
          unit: minute
          requests_per_unit: 1
      - key: PATH
        rate_limit:
          unit: minute
          requests_per_unit: 100
EOF
```

### 4. Deploy the global rate limit service

Deploy the Envoy global rate limit service. It reads the `ratelimit-config` `ConfigMap` and exposes a gRPC endpoint used by the ingress gateway.

``` sh
kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.25/samples/ratelimit/rate-limit-service.yaml
```

### 5. Configure EnvoyFilter to use the global rate limit service

Insert the Envoy HTTP Rate Limit filter into the HTTP filter chain and point it at the `ratelimit` gRPC service.

```sh
kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: filter-ratelimit
  namespace: default
spec:
  workloadSelector:
    labels:
      gateway.networking.k8s.io/gateway-name: httpbin-waypoint
  configPatches:
    - applyTo: CLUSTER
      match:
        context: SIDECAR_INBOUND
      patch:
        operation: ADD
        value:
          name: rate_limit_cluster
          type: STRICT_DNS
          connect_timeout: 0.25s
          lb_policy: ROUND_ROBIN
          http2_protocol_options: {}
          load_assignment:
            cluster_name: rate_limit_cluster
            endpoints:
            - lb_endpoints:
              - endpoint:
                  address:
                    socket_address:
                      address: ratelimit.default.svc.cluster.local
                      port_value: 8081
    - applyTo: HTTP_FILTER
      match:
        context: SIDECAR_INBOUND
        listener:
          filterChain:
            filter:
              name: "envoy.filters.network.http_connection_manager"
              subFilter:
                name: "envoy.filters.http.router"
      patch:
        operation: INSERT_BEFORE
        value:
          name: envoy.filters.http.ratelimit
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.ratelimit.v3.RateLimit
            domain: ratelimit
            failure_mode_deny: true
            timeout: 10s
            rate_limit_service:
              grpc_service:
                envoy_grpc:
                  cluster_name: rate_limit_cluster
                  authority: ratelimit.default.svc.cluster.local
              transport_api_version: V3
EOF
```

Apply a second `EnvoyFilter` that maps the `:path` request header into the `PATH` descriptor.

``` sh
kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: filter-ratelimit-svc
  namespace: default
spec:
  workloadSelector:
    labels:
      gateway.networking.k8s.io/gateway-name: httpbin-waypoint
  configPatches:
    - applyTo: VIRTUAL_HOST
      match:
        context: SIDECAR_INBOUND
        routeConfiguration:
          vhost:
            name: ""
            route:
              action: ANY
      patch:
        operation: MERGE
        # Applies the rate limit rules.
        value:
          rate_limits:
            - actions:
              - request_headers:
                  header_name: ":path"
                  descriptor_key: "PATH"
EOF
```

### 6. Test rate limit against httpbin

``` sh
kubectl apply -f ./samples/sleep/sleep.yaml
sleep 10
export SLEEP_POD=$(kubectl get pod -l app=sleep -o jsonpath='{.items[0].metadata.name}')
```

``` sh
for i in {0..2}; do kubectl exec -it $SLEEP_POD -- curl -s "http://httpbin:8000/status/200" -o /dev/null -w "%{http_code}\n"; sleep 1; done
```

Expected output:

``` sh
200
429
429
```

The output shows HTTP status codes:

- **200**: OK. The request was successful.
- **429**: Too Many Requests. The request was rejected because the rate limit was exceeded.
