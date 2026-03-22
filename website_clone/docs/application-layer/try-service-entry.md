---
sidebar_position: 5
title: Try Service Entry
---

Service Entry enables you to extend Istio's service registry by adding entries for external services. This allows applications in the mesh to discover, access, and apply traffic policies to services that are not automatically discovered in the service mesh. With Kmesh's DNS Controller for Workloads, Service Entry now supports dynamic DNS resolution, making it seamless to integrate external services with changing IP addresses.

## What is Service Entry?

Service Entry is a critical Istio resource that allows you to:

- **Add external services** to the mesh's internal service registry
- **Enable traffic management** (routing, load balancing, retries) for external services
- **Support multiple resolution modes** including DNS, STATIC, and NONE
- **Control egress traffic** with consistent policies

Kmesh enhances Service Entry with intelligent DNS resolution that automatically handles hostname-to-IP address mapping for external services, ensuring seamless connectivity even when backend addresses change dynamically.

## Preparation

Before getting started, ensure you have completed the following steps:

1. **Make default namespace managed by Kmesh**
2. **Deploy Httpbin as sample application and Sleep as curl client**
3. **Install waypoint for default namespace**

   _For detailed instructions on the above steps, refer to [Install Waypoint | Kmesh](/docs/application-layer/install_waypoint.md#preparation)_

## Verify Environment Setup

Confirm that the httpbin and sleep applications are running properly:

```bash
kubectl get pods
```

You should see both services in Running state:

```bash
NAME                       READY   STATUS    RESTARTS   AGE
httpbin-6f4464f6c5-h9x2p   1/1     Running   0          30s
sleep-9454cc476-86vgb      1/1     Running   0          5m
```

## Understanding Service Entry Configuration

### Basic Service Entry with DNS Resolution

Let's create a Service Entry that defines a virtual external service. This example demonstrates how Kmesh's DNS Controller automatically resolves the backend hostname:

```bash
kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1alpha3
kind: ServiceEntry
metadata:
  name: external-fake-svc
  namespace: default
spec:
  exportTo:
    - "*"
  hosts:
    - kmesh-fake.com
  ports:
    - name: http
      number: 80
      protocol: HTTP
  endpoints:
    - address: httpbin.default.svc.cluster.local
      ports:
        http: 8000
  resolution: DNS
EOF
```

### Key Configuration Fields

- **`hosts`**: Virtual hostname(s) that clients use to access the service (`kmesh-fake.com`)
- **`ports`**: Port definitions including number, name, and protocol
- **`endpoints.address`**: Backend service address - can be a hostname (DNS resolution) or IP address
- **`resolution: DNS`**: Kmesh's DNS Controller will automatically resolve the hostname to IP addresses and keep them updated
- **`exportTo`**: Controls visibility of this Service Entry across namespaces (`*` means all namespaces)

### How DNS Resolution Works

When you configure `resolution: DNS`:

1. Kmesh's **Workload DNS Controller** detects the Service Entry with hostname-based endpoints
2. The controller performs asynchronous DNS lookups to resolve hostnames to IP addresses
3. If addresses are not immediately available, the controller queues the workload for retry
4. Once resolved, workloads are updated with the actual IP addresses
5. The controller periodically refreshes DNS records to handle IP changes

This dynamic resolution ensures your service mesh remains connected even when external service IPs change.

## Test Service Entry Configuration

After configuring the Service Entry, we can verify that it works correctly through the following tests:

### 1. Basic Connectivity Test

Test access to the virtual external service:

```bash
kubectl exec deploy/sleep -- curl -s http://kmesh-fake.com/headers
```

You should see a response from the httpbin service, notice that the Host header has changed to our defined virtual hostname:

```json
{
  "headers": {
    "Accept": "*/*",
    "Host": "kmesh-fake.com",
    "User-Agent": "curl/8.16.0"
  }
}
```

### 2. Detailed Request Information Verification

Get complete request information:

```bash
kubectl exec deploy/sleep -- curl -s http://kmesh-fake.com/get
```

The output shows the request was successfully routed to the httpbin service:

```json
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "kmesh-fake.com",
    "User-Agent": "curl/8.16.0"
  },
  "origin": "10.244.1.6",
  "url": "http://kmesh-fake.com/get"
}
```

### 3. HTTP Status Code Test

Test different HTTP status code responses:

```bash
# Test normal status code
kubectl exec deploy/sleep -- curl -s http://kmesh-fake.com/status/200

# Test specific status code and display the return code
kubectl exec deploy/sleep -- curl -s -o /dev/null -w "%{http_code}\n" http://kmesh-fake.com/status/418
```

The second command should return the HTTP status code:

```txt
418
```

### 4. Response Header Check

Check complete response header information:

```bash
kubectl exec deploy/sleep -- curl -IsS http://kmesh-fake.com/headers
```

You should see response headers containing Envoy proxy and routing information:

```txt
HTTP/1.1 200 OK
server: envoy
date: Wed, 08 Oct 2025 07:51:51 GMT
content-type: application/json
content-length: 78
access-control-allow-origin: *
access-control-allow-credentials: true
x-envoy-upstream-service-time: 1
x-envoy-decorator-operation: httpbin.default.svc.cluster.local:8000/*
```

## Advanced Use Cases

### Use Case 1: Real External Service with DNS Resolution

Access actual external services on the internet with automatic DNS resolution:

```bash
kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1alpha3
kind: ServiceEntry
metadata:
  name: external-httpbin-org
  namespace: default
spec:
  hosts:
    - httpbin.org
  ports:
    - number: 80
      name: http
      protocol: HTTP
  resolution: DNS
  location: MESH_EXTERNAL
EOF
```

**Key points:**

- No explicit `endpoints` defined - Kmesh resolves `httpbin.org` directly via DNS
- `location: MESH_EXTERNAL` indicates this is an external service
- DNS Controller automatically handles IP resolution and updates

**Test external service access:**

```bash
kubectl exec deploy/sleep -- curl -s http://httpbin.org/headers
```

Expected response from the real httpbin.org service:

```json
{
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "User-Agent": "curl/8.16.0"
  }
}
```

### Use Case 2: Static IP Endpoints

For services with stable IP addresses, use `STATIC` resolution to bypass DNS:

```bash
kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1alpha3
kind: ServiceEntry
metadata:
  name: external-static-svc
  namespace: default
spec:
  hosts:
    - static-service.example.com
  ports:
    - number: 443
      name: https
      protocol: HTTPS
  resolution: STATIC
  endpoints:
    - address: 192.168.1.100
    - address: 192.168.1.101
EOF
```

**Use STATIC resolution when:**

- Backend services have fixed IP addresses
- You want to avoid DNS lookup overhead
- You need precise control over endpoint addresses

### Use Case 3: Multiple Endpoints with Load Balancing

Configure Service Entry with multiple backends for high availability:

```bash
kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1alpha3
kind: ServiceEntry
metadata:
  name: multi-endpoint-svc
  namespace: default
spec:
  hosts:
    - multi-backend.example.com
  ports:
    - number: 80
      name: http
      protocol: HTTP
  resolution: DNS
  endpoints:
    - address: backend1.example.com
      ports:
        http: 8080
    - address: backend2.example.com
      ports:
        http: 8080
    - address: backend3.example.com
      ports:
        http: 8080
EOF
```

Kmesh's DNS Controller will:

- Resolve each backend hostname independently
- Maintain current IP addresses for all endpoints
- Enable built-in load balancing across all resolved addresses

## Test Service Entry Configuration

After configuring the Service Entry, we can verify that it works correctly through the following tests:

### 1. Basic Connectivity Test

Test access to the virtual external service:

```bash
kubectl exec deploy/sleep -- curl -s http://kmesh-fake.com/headers
```

You should see a response from the httpbin service, notice that the Host header has changed to our defined virtual hostname:

```json
{
  "headers": {
    "Accept": "*/*",
    "Host": "kmesh-fake.com",
    "User-Agent": "curl/8.16.0"
  }
}
```

### 2. Detailed Request Information Verification

Get complete request information:

```bash
kubectl exec deploy/sleep -- curl -s http://kmesh-fake.com/get
```

The output shows the request was successfully routed to the httpbin service:

```json
{
  "args": {},
  "headers": {
    "Accept": "*/*",
    "Host": "kmesh-fake.com",
    "User-Agent": "curl/8.16.0"
  },
  "origin": "10.244.1.6",
  "url": "http://kmesh-fake.com/get"
}
```

### 3. HTTP Status Code Test

Test different HTTP status code responses:

```bash
# Test normal status code
kubectl exec deploy/sleep -- curl -s http://kmesh-fake.com/status/200

# Test specific status code and display the return code
kubectl exec deploy/sleep -- curl -s -o /dev/null -w "%{http_code}\n" http://kmesh-fake.com/status/418
```

The second command should return the HTTP status code:

```txt
418
```

### 4. Response Header Check

Check complete response header information:

```bash
kubectl exec deploy/sleep -- curl -IsS http://kmesh-fake.com/headers
```

You should see response headers containing Envoy proxy and routing information:

```txt
HTTP/1.1 200 OK
server: envoy
date: Wed, 08 Oct 2025 07:51:51 GMT
content-type: application/json
content-length: 78
access-control-allow-origin: *
access-control-allow-credentials: true
x-envoy-upstream-service-time: 1
x-envoy-decorator-operation: httpbin.default.svc.cluster.local:8000/*
```

## Troubleshooting

### Service Entry Not Working

If you can't access the external service:

1. **Check Service Entry status:**

   ```bash
   kubectl get serviceentry -n default
   kubectl describe serviceentry external-fake-svc -n default
   ```

2. **Verify DNS resolution (for DNS type):**

   ```bash
   # From within the sleep pod
   kubectl exec deploy/sleep -- nslookup httpbin.default.svc.cluster.local
   ```

3. **Check Kmesh logs for DNS resolution issues:**

   ```bash
   kubectl logs -n kmesh-system -l app=kmesh -c kmesh --tail=50 | grep -i dns
   ```

### Common Issues

**Issue: Connection timeout or refused**

- Ensure the backend service is reachable from the cluster
- Verify firewall rules allow egress traffic
- Check that endpoint addresses are correct

**Issue: DNS resolution failures**

- Confirm DNS server is accessible from the cluster
- Validate hostname spellings in `endpoints.address`
- Check if internal DNS is working: `kubectl exec deploy/sleep -- nslookup kubernetes.default`

**Issue: Workload not receiving updated IPs**

- Kmesh's DNS Controller refreshes periodically - allow time for propagation
- Check controller logs for any errors during DNS lookup
- Verify Service Entry `resolution` is set to `DNS` (not `STATIC`)

## Cleanup

After completing the tests, delete the created Service Entry resources:

```bash
# Delete all Service Entry resources
kubectl delete serviceentry external-fake-svc -n default
kubectl delete serviceentry external-httpbin-org -n default
kubectl delete serviceentry external-static-svc -n default 2>/dev/null || true
kubectl delete serviceentry multi-endpoint-svc -n default 2>/dev/null || true
```

If you're not planning to continue with subsequent experiments, refer to the [Install Waypoint/Cleanup](/docs/application-layer/install_waypoint.md#cleanup) section for instructions on removing the waypoint and cleaning up applications.

## Summary

Through this guide, you learned how to:

1. **Add external services** to the Istio service mesh using Service Entry
2. **Configure DNS-based resolution** leveraging Kmesh's intelligent DNS Controller
3. **Use static IP endpoints** for services with fixed addresses
4. **Set up multiple backends** with automatic load balancing
5. **Access real external services** on the internet from within the mesh
6. **Troubleshoot common issues** related to Service Entry configuration

### Key Takeaways

- **Service Entry extends your mesh** beyond automatically discovered services
- **Kmesh's DNS Controller** provides dynamic, automatic hostname resolution
- **Multiple resolution modes** (DNS, STATIC, NONE) support different use cases
- **DNS resolution is asynchronous** and includes retry logic for reliability
- **Service Entry works seamlessly** with other Istio features like traffic routing and policies

Service Entry is an essential tool for managing external service dependencies in Istio, providing consistent visibility, control, and reliability for services outside your mesh.
