## Step 1. 部署Kmesh和isitod（>=1.24）

## Step 2. 部署sleep和httpbin

## Step 3. 为httpbin部署waypoint

```sh
kmeshctl waypoint apply -n default --name httpbin-waypoint
kubectl label service httpbin istio.io/use-waypoint=httpbin-waypoint
```

## Step 4. 部署envoyFilter

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

## Step 5. 通过istioctl查看waypoint中的envoy filter配置信息

```sh
istioctl proxy-config all httpbin-waypoint-c9944bb76-xnkb6 -ojson | grep ratelimit -A 20
```

## Step 6. 在其中能够找到如下结果，说明配置已经下发到waypoint中

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

## Step 7. 通过sleep访问httpbin，看限流是否起作用

```sh
root@kurator-linux-zirain:~/.istioctl/bin# k exec -it sleep-5fcd8fd6c8-689t2 -- curl -H 'quota:medium' http://httpbin:8000/headers 
{"headers":{"Accept":"*/*","Host":"httpbin:8000","Quota":"medium","User-Agent":"curl/8.13.0"}}
root@kurator-linux-zirain:~/.istioctl/bin# k exec -it sleep-5fcd8fd6c8-689t2 -- curl -H 'quota:medium' http://httpbin:8000/headers 
{"headers":{"Accept":"*/*","Host":"httpbin:8000","Quota":"medium","User-Agent":"curl/8.13.0"}}
root@kurator-linux-zirain:~/.istioctl/bin# k exec -it sleep-5fcd8fd6c8-689t2 -- curl -H 'quota:medium' http://httpbin:8000/headers 
{"headers":{"Accept":"*/*","Host":"httpbin:8000","Quota":"medium","User-Agent":"curl/8.13.0"}}
root@kurator-linux-zirain:~/.istioctl/bin# k exec -it sleep-5fcd8fd6c8-689t2 -- curl -H 'quota:medium' http://httpbin:8000/headers 
local_rate_limitedroot
```