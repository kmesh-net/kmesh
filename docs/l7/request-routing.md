
# Request Routing in Kmesh

This document explains how to configure HTTP request routing at Layer 7 using Kmesh. Request routing allows you to control how traffic is directed to different backend services based on URL paths.

## Prerequisites

Before starting, you should have:

- A Kubernetes cluster with Istio and Kmesh installed
- Gateway API CRDs applied
- Deployed services, such as httpbin and sleep
- The appropriate label set on your namespace to enable Kmesh

## Use Case: Path-Based Routing

This example routes traffic to two different versions of the httpbin service, depending on the requested URL path.

- Requests to paths beginning with /v1 are sent to httpbin-v1
- Requests to paths beginning with /v2 are sent to httpbin-v2

## Step 1: Deploy Sample Workloads

```bash
kubectl create namespace example
kubectl label namespace example istio.io/dataplane-mode=Kmesh
kubectl apply -n example -f samples/httpbin/httpbin-v1.yaml
kubectl apply -n example -f samples/httpbin/httpbin-v2.yaml
kubectl apply -n example -f samples/sleep/sleep.yaml
```

## Step 2: Define Gateway and Route

Save this configuration as http-route.yaml

```yaml
apiVersion: gateway.networking.k8s.io/v1beta1
kind: HTTPRoute
meta
  name: http-route
  namespace: example
spec:
  parentRefs:
  - name: example-gateway
  rules:
  - matches:
    - path:
        type: PathPrefix
        value: /v1
    backendRefs:
    - name: httpbin-v1
      port: 8000
  - matches:
    - path:
        type: PathPrefix
        value: /v2
    backendRefs:
    - name: httpbin-v2
      port: 8000
```

Apply the configuration:

```bash
kubectl apply -f http-route.yaml
```

## Step 3: Verify Routing

Open a shell in the sleep pod

```bash
kubectl -n example exec deploy/sleep -- bash
```

From within the pod, run

```bash
curl http://httpbin.example.svc.cluster.local:8000/v1/status/200
curl http://httpbin.example.svc.cluster.local:8000/v2/status/200
```

You should see that the path for /v1 gets a response from httpbin-v1 and /v2 gets a response from httpbin-v2.

## Notes and Limitations

Header-based and regex path matching may require further validation. These instructions assume the example-gateway resource is present and working as expected.

## Related References

Kmesh issue <https://github.com/kmesh-net/kmesh/issues/600>

Istio Request Routing: <https://istio.io/latest/docs/tasks/traffic-management/request-routing>
