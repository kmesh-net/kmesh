--- 
title: Rate Limiting Test Guide
authors:
- "@LiZhenCheng9527 @zrggw"
reviews:
-
approves:
-

create-date: 2025-5-29

---

This document provides a step-by-step guide on how to test the local rate limiting functionality of kmesh. It covers deploying the necessary components, configuring traffic rules, and observing the rate limiting behavior.

## Step 1. Deploy Kmesh and istiod (>=1.24)

Please read [Quick Start](https://kmesh.net/docs/setup/quick-start) to complete the deployment of kmesh.

## Step 2. Deploy sleep and httpbin

We will deploy `httpbin` as the backend service for receiving requests and `sleep` as the client for sending requests.

``` sh
kubectl apply -f samples/sleep/sleep.yaml
kubectl apply -f sample/httpbin/httpbin.yaml
```

## Step 3. Deploy waypoint for httpbin

First, if you haven't installed the Kubernetes Gateway API CRDs, run the following command to install.

``` sh
kubectl get crd gateways.gateway.networking.k8s.io &> /dev/null || \
  { kubectl kustomize "github.com/kubernetes-sigs/gateway-api/config/crd/experimental?ref=444631bfe06f3bcca5d0eadf1857eac1d369421d" | kubectl apply -f -; }
```

Next, create a dedicated Waypoint proxy for the `httpbin` service and label the service to direct its traffic through this Waypoint.

```sh
kmeshctl waypoint apply -n default --name httpbin-waypoint --image ghcr.io/kmesh-net/waypoint:latest

kubectl label service httpbin istio.io/use-waypoint=httpbin-waypoint
```

## Step 4. Deploy envoyFilter

This `EnvoyFilter` resource injects a local rate-limiting filter into the `httpbin` service's Waypoint proxy. The filter is configured with the following rules:
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

## Step 5. View the envoy filter configuration in waypoint through istioctl

To verify the configuration, first get the name of the Waypoint pod, then use `istioctl` to inspect its configuration.

```sh
export WAYPOINT_POD=$(kubectl get pod -l gateway.networking.k8s.io/gateway-name=httpbin-waypoint -o jsonpath='{.items[0].metadata.name}')
istioctl proxy-config all $WAYPOINT_POD -ojson | grep ratelimit -A 20
```

## Step 6. Find the following results, which means the configuration has been sent to waypoint

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

## Step 7. Access httpbin through sleep to see if the rate limit is working

Now, let's send requests from the `sleep` pod to the `httpbin` service to test the rate limit rules.

First, get the name of the `sleep` pod:
```sh
export SLEEP_POD=$(kubectl get pod -l app=sleep -o jsonpath='{.items[0].metadata.name}')
```

### Test Case 1: "medium" quota

The rule for `quota: medium` allows 3 requests. The fourth request should be rate-limited.

```sh
kubectl exec -it $SLEEP_POD -- curl -H 'quota:medium' http://httpbin:8000/headers
kubectl exec -it $SLEEP_POD -- curl -H 'quota:medium' http://httpbin:8000/headers
kubectl exec -it $SLEEP_POD -- curl -H 'quota:medium' http://httpbin:8000/headers
kubectl exec -it $SLEEP_POD -- curl -H 'quota:medium' http://httpbin:8000/headers
```
Expected output for the fourth command:
```
local_rate_limited
```

### Test Case 2: "low" quota

The rule for `quota: low` allows only 1 request. The second request should be rate-limited.

```sh
kubectl exec -it $SLEEP_POD -- curl -H 'quota:low' http://httpbin:8000/headers
kubectl exec -it $SLEEP_POD -- curl -H 'quota:low' http://httpbin:8000/headers
```
Expected output for the second command:
```
local_rate_limited
```
