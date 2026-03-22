---
sidebar_position: 3
title: TCP Authorization in XDP
---

## Authorization in XDP

Previously, we launched the [userspace authorization feature](/docs/transpot-layer/tcp-authorization.md), where authorization results were verified in userspace. This document explains how to enable authentication directly within the XDP program. Currently, XDP-based authentication supports verification based on port and IP addresses only.

### How to enable XDP-based authentication

We can use `kmeshctl` to enable XDP-based authentication:

```bash
./kmeshctl authz enable
```

To modify BPF log level:

```bash
./kmeshctl log <$kmeshnode1> --set bpf:debug
```

## Configure Deny Authorization Policies

### Configure Destination Port Deny Authorization Policy

Create a "deny-by-dstport" authorization policy for the Fortio workload that denies requests to the specified port address. In this example, traffic sent to port 8080 is denied:

```yaml
# deny-by-dstport.yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: deny-by-dstport
spec:
  selector:
    matchLabels:
      app: fortio-server
  action: DENY
  rules:
  - to:
    - operation:
        ports:
        - "8080"
```

Apply the policy:

```bash
kubectl apply -f deny-by-dstport.yaml
```

#### Testing the Policy

The status code returned by the Fortio traffic confirms that traffic sent to port 8080 has been denied:

```bash
kubectl exec -it fortio-client-deployment-6966bf9488-tpwpj -- fortio load -c 1 -n 1 -qps 0 -jitter=true 10.244.0.7:8080
```

Expected output:

```text
...
IP addresses distribution:
10.244.0.7:8080: 1
Code  -1 : 1 (100.0 %)
Response Header Sizes : count 1 avg 0 +/- 0 min 0 max 0 sum 0
Response Body/Total Sizes : count 1 avg 0 +/- 0 min 0 max 0 sum 0
All done 1 calls (plus 0 warmup) 3005.022 ms avg, 0.3 qps
```

Specific information will also be printed in the logs recorded by Kmesh:

```bash
kubectl logs -f kmesh-vlxhd -n kmesh-system
```

Expected output:

```log
...
time="2024-12-25T15:23:12+08:00" level=info msg="[AUTH] DEBUG: port 8080 in destination_ports, matched" subsys=ebpf
time="2024-12-25T15:23:12+08:00" level=info msg="[AUTH] DEBUG: rule matched, action: DENY" subsys=ebpf
```

### Configure Source IP Deny Authorization Policy

Create a policy to deny traffic from a specific source IP:

```yaml
# deny-by-srcip.yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-by-srcip1
  namespace: default
spec:
  selector:
    matchLabels:
      app: fortio-server
  action: DENY
  rules:
  - from:
    - source:
        ipBlocks:
        - 10.244.1.36
```

Apply the policy:

```bash
kubectl apply -f deny-by-srcip.yaml
```

#### Testing the Policy

The status code returned by the Fortio traffic confirms that traffic sent from IP 10.244.1.36 has been denied:

```bash
# The IP address of fortio-client-deployment-6966bf9488-m96qp is 10.244.1.36
kubectl exec -it fortio-client-deployment-6966bf9488-m96qp -- fortio load -c 1 -n 1 -qps 0 -jitter=true 10.244.0.36:8080
```

Expected output:

```text
...
IP addresses distribution:
10.244.0.36:8080: 1
Code  -1 : 1 (100.0 %)
Response Header Sizes : count 1 avg 0 +/- 0 min 0 max 0 sum 0
Response Body/Total Sizes : count 1 avg 0 +/- 0 min 0 max 0 sum 0
All done 1 calls (plus 0 warmup) 3005.563 ms avg, 0.3 qps
```

Specific information will also be printed in the logs recorded by Kmesh:

```bash
kubectl logs -f kmesh-vlxhd -n kmesh-system
```

Expected output:

```log
...
time="2024-12-26T15:05:26+08:00" level=info msg="[AUTH] DEBUG: rule matched, action: DENY" subsys=ebpf
time="2024-12-26T15:06:14+08:00" level=info msg="[AUTH] DEBUG: no ports configured, matching by default" subsys=ebpf
time="2024-12-26T15:06:14+08:00" level=info msg="[AUTH] DEBUG: IPv4 match srcip: Rule IP: af40124, Prefix Length: 32, Target IP: af40124\n" subsys=ebpf
```

### Configure Destination IP Deny Authorization Policy

Create a policy to deny traffic to a specific destination IP:

```yaml
# deny-by-dstip.yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: deny-dstip
spec:
  selector:
    matchLabels:
      app: fortio-server
  action: DENY
  rules:
  - when:
    - key: destination.ip
      values: ["10.244.0.36"]
```

Apply the policy:

```bash
kubectl apply -f deny-by-dstip.yaml
```

#### Testing the Policy

The status code returned by the Fortio traffic confirms that traffic sent to IP 10.244.0.36 has been denied:

```bash
kubectl exec -it fortio-client-deployment-6966bf9488-m96qp -- fortio load -c 1 -n 1 -qps 0 -jitter=true 10.244.0.36:8080
```

Expected output:

```text
...
10.244.0.36:8080: 1
Code  -1 : 1 (100.0 %)
Response Header Sizes : count 1 avg 0 +/- 0 min 0 max 0 sum 0
Response Body/Total Sizes : count 1 avg 0 +/- 0 min 0 max 0 sum 0
All done 1 calls (plus 0 warmup) 3004.974 ms avg, 0.3 qps
```

Specific information will also be printed in the logs recorded by Kmesh:

```bash
kubectl logs -f kmesh-vlxhd -n kmesh-system
```

Expected output:

```log
...
time="2024-12-26T15:05:22+08:00" level=info msg="[AUTH] DEBUG: rule matched, action: DENY" subsys=ebpf
time="2024-12-26T15:05:26+08:00" level=info msg="[AUTH] DEBUG: no ports configured, matching by default" subsys=ebpf
time="2024-12-26T15:05:26+08:00" level=info msg="[AUTH] DEBUG: IPv4 match dstip: Rule IP: af40024, Prefix Length: 32, Target IP: af40024\n" subsys=ebpf
```
