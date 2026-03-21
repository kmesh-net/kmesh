# ADS Mode Deployment and Usage Guide

ADS (Aggregated Discovery Service) mode, or **Kernel-Native mode**, in Kmesh enables L4 and simple L7 (HTTP) traffic governance directly within the kernel using eBPF. In this mode, Kmesh acts as a standard xDS client, subscribing to CDS, EDS, LDS, and RDS resources from the control plane (e.g., Istiod) using the ADS protocol.

## Prerequisites
- A running Kubernetes cluster (v1.23+ recommended).
- Istio control plane (Istiod) installed and running in the `istio-system` namespace.
- Kernel version 4.19+ (for L4 features) or 5.10+ (for L7 features).

## Deployment Guide

### 1. Configure Kmesh in ADS Mode
By default, the daemonset command uses `dual-engine` mode. To enable ADS mode, modify the command argument in `deploy/yaml/kmesh.yaml`:

```yaml
# deploy/yaml/kmesh.yaml
args: [ "./start_kmesh.sh --mode=kernel-native --enable-bypass=false" ]
```

### 2. Deploy Kmesh Daemonset
Apply the deployment manifest to your cluster:

```bash
kubectl apply -f deploy/yaml/kmesh.yaml
```

Wait until all Kmesh pods are running:
```bash
kubectl get pods -n kmesh-system
```

### 3. Enable Kmesh for a Namespace
Label the target namespace to manage its Pod traffic using Kmesh:

```bash
kubectl label namespace <your-namespace> istio.io/dataplane-mode=kmesh
```

Newly created Pods in this namespace will be intercepted and managed by Kmesh.

## Verification

Check the Kmesh pod logs to confirm successful xDS subscription:
```bash
kubectl logs -n kmesh-system <kmesh-pod-name>
```

Verify the BPF maps are successfully populated and the configuration is applied. You can access the Kmesh admin console by port-forwarding the status port (15200) from a Kmesh pod to your local machine:

```bash
# Port-forward the Kmesh status port
kubectl port-forward -n kmesh-system <kmesh-pod-name> 15200:15200

# In a separate terminal, query the BPF configuration dump
curl http://localhost:15200/debug/config_dump/bpf/kernel-native
```

## Usage Examples

### 1. HTTP Routing
You can use standard Istio `VirtualService` to route traffic based on host or path:

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: reviews-route
spec:
  hosts:
  - reviews
  http:
  - match:
    - uri:
        prefix: /v2
    route:
    - destination:
        host: reviews
        subset: v2
  - route:
    - destination:
        host: reviews
        subset: v1
```

### 2. Load Balancing
Configure Load Balancing using `DestinationRule`:

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: reviews-lb
spec:
  host: reviews
  trafficPolicy:
    loadBalancer:
      simple: LEAST_CONN
```

### 3. Grayscale (Canary) Release
Distribute traffic by percentage:

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: reviews-canary
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
```

### 4. TCP Grayscale
L4 traffic distribution is also supported:

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: tcp-canary
spec:
  hosts:
  - tcp-echo
  tcp:
  - route:
    - destination:
        host: tcp-echo
        subset: v1
      weight: 80
    - destination:
        host: tcp-echo
        subset: v2
      weight: 20
```
