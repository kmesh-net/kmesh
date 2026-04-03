---
sidebar_position: 1
title: TCP Authorization
---


This guide shows you how to set up authorization policy for TCP traffic in Kmesh.

## Before you begin

- Understand the [AuthorizationPolicy](#authorizationpolicy) concept
- Install Kmesh
  - Please refer to the [quickstart guide](/docs/setup/quick-start.md)
- Deploy the Sample Applications and configure them to be managed by Kmesh
  - Please refer to [deploy applications](/docs/setup/quick-start.md#deploy-the-sample-applications)
  - Modify the replicas to 2 in sleep deployment:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sleep
spec:
  replicas: 2
  selector:
    matchLabels:
      app: sleep
  template:
    metadata:
      labels:
        app: sleep
    spec:
      terminationGracePeriodSeconds: 0
      serviceAccountName: sleep
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
```

- Verify application status to ensure the service application is managed by Kmesh:

```bash
# Check pod status
kubectl get pod -o wide | grep sleep
```

Expected output:

```bash
NAME                                READY   STATUS    RESTARTS   AGE     IP            NODE              NOMINATED NODE   READINESS GATES
sleep-78ff5975c6-phhll              1/1     Running   0          30h     10.244.2.22   ambient-worker    <none>           <none>
sleep-78ff5975c6-plh7r              1/1     Running   0          30h     10.244.1.46   ambient-worker2   <none>           <none>
```

```bash
# Verify Kmesh management
kubectl describe pod httpbin-65975d4c6f-96kgw | grep Annotations
```

Expected output:

```text
Annotations:      kmesh.net/redirection: enabled
```

## Configure ALLOW Authorization Policy

1. Create an "allow-by-srcip" authorization policy for the httpbin workload:

```bash
kubectl apply -f - <<EOF
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-by-srcip
  namespace: default
spec:
  selector:
    matchLabels:
      app: httpbin
  action: ALLOW
  rules:
  - from:
    - source:
        ipBlocks:
        - 10.244.1.46/32
EOF
```

> This policy allows requests only from the specified IP address `10.244.1.46/32`, which corresponds to the pod `sleep-78ff5975c6-plh7r`.

2. Verify that requests from the allowed IP are successful:

```bash
kubectl exec sleep-78ff5975c6-plh7r -- curl http://httpbin:8000/headers
```

Expected output:

```json
{
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin:8000",
    "User-Agent": "curl/8.5.0"
  }
}
```

3. Verify that requests from other IPs are denied:

```bash
kubectl exec sleep-78ff5975c6-phhll -- curl http://httpbin:8000/headers
```

Expected output:

```text
curl: (56) Recv failure: Connection reset by peer
```

4. Clean up the AuthorizationPolicy:

```bash
kubectl delete AuthorizationPolicy allow-by-srcip -n default
```

## Configure DENY Authorization Policy

1. Create a "deny-by-srcip" authorization policy for the httpbin workload:

```bash
kubectl apply -f - <<EOF
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: deny-by-srcip
  namespace: default
spec:
  selector:
    matchLabels:
      app: httpbin
  action: DENY
  rules:
  - from:
    - source:
        ipBlocks:
        - 10.244.1.46/32
EOF
```

> This policy denies requests from the specified IP address `10.244.1.46/32`, which corresponds to the pod `sleep-78ff5975c6-plh7r`.

2. Verify that requests from the denied IP are blocked:

```bash
kubectl exec sleep-78ff5975c6-plh7r -- curl "http://httpbin:8000/headers"
```

Expected output:

```text
curl: (56) Recv failure: Connection reset by peer
```

3. Verify that requests from other IPs are allowed:

```bash
kubectl exec sleep-78ff5975c6-phhll -- curl "http://httpbin:8000/headers"
```

Expected output:

```json
{
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin:8000",
    "User-Agent": "curl/8.5.0"
  }
}
```

4. Clean up the AuthorizationPolicy:

```bash
kubectl delete AuthorizationPolicy deny-by-srcip -n default
```

## Clean up

Please refer to the [cleanup guide](/docs/setup/quick-start.md#clean-up)

## AuthorizationPolicy

### AuthorizationPolicy Fields

| Field   | Type     | Description                                                                                                                                                                                                                                        | Required |
|---------|----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| -------- |
| `rules` | `Rule[]` | Optional. A list of rules to match the request. A match occurs when at least one rule matches the request. If not set, the match will never occur. This is equivalent to setting a default of deny for the target workloads if the action is ALLOW. | No       |

### Rule

Rule matches requests from a list of sources that perform a list of operations subject to a list of conditions. A match occurs when at least one source, one operation and all conditions match the request. An empty rule is always matched.

| Field  | Type     | Description                                                                           | Required |
|--------|----------|---------------------------------------------------------------------------------------| -------- |
| `from` | `From[]` | Optional. `from` specifies the source of a request. If not set, any source is allowed.| No       |
| `to`   | `To[]`   | Optional. `to` specifies the operation of a request. If not set, any operation is allowed. | No       |

#### Rule.From

From includes a list of sources.

| Field    | Type     | Description                               | Required |
|----------|----------|-------------------------------------------| -------- |
| `source` | `Source` | Source specifies the source of a request. | No       |

#### Rule.To

To includes a list of operations.

| Field       | Type        | Description                                     | Required |
|-------------|-------------|-------------------------------------------------| -------- |
| `operation` | `Operation` | Operation specifies the operation of a request. | No       |

### Source

Source specifies the source identities of a request. Fields in the source are ANDed together.

For example, the following source matches if the principal is `admin` or `dev` AND the namespace is `prod` or `test` AND the ip is not `203.0.113.4`.

```yaml
principals: ["admin", "dev"]
namespaces: ["prod", "test"]
notIpBlocks: ["203.0.113.4"]
```

| Field           | Type       | Description                                                                                                                                                                              | Required |
|-----------------|------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| -------- |
| `principals`    | `string[]` | Optional. A list of peer identities derived from the peer certificate. The peer identity is in the format of `"<TRUST_DOMAIN>/ns/<NAMESPACE>/sa/<SERVICE_ACCOUNT>"`, for example, `"cluster.local/ns/default/sa/productpage"`. This field requires mTLS enabled and is the same as the `source.principal` attribute. If not set, any principal is allowed. | No       |
| `notPrincipals` | `string[]` | Optional. A list of negative match of peer identities.                                                                                                                                   | No       |
| `namespaces`    | `string[]` | Optional. A list of namespaces derived from the peer certificate. This field requires mTLS enabled and is the same as the `source.namespace` attribute. If not set, any namespace is allowed. | No       |
| `notNamespaces` | `string[]` | Optional. A list of negative match of namespaces.                                                                                                                                        | No       |
| `ipBlocks`      | `string[]` | Optional. A list of IP blocks, populated from the source address of the IP packet. Single IP (e.g. `203.0.113.4`) and CIDR (e.g. `203.0.113.0/24`) are supported. This is the same as the `source.ip` attribute. If not set, any IP is allowed. | No       |
| `notIpBlocks`   | `string[]` | Optional. A list of negative match of IP blocks.                                                                                                                                         | No       |

### Operation

Operation specifies the operations of a request. Fields in the operation are ANDed together.

| Field      | Type       | Description                                                                               | Required |
|------------|------------|-------------------------------------------------------------------------------------------| -------- |
| `ports`    | `string[]` | Optional. A list of ports as specified in the connection. If not set, any port is allowed.| No       |
| `notPorts` | `string[]` | Optional. A list of negative match of ports as specified in the connection.               | No       |
