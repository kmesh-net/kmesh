# IPSec & Offload Authorization E2E Test Guide

This document provides a step-by-step guide for executing the IPSec and Offload Authorization E2E tests for Kmesh. These tests ensure the reliability, security, and functionality of the IPSec feature and the Offload Authorization mechanisms.

## Prerequisites

Before running the tests, ensure the following:

- **Kubernetes Cluster**: A two-node Kubernetes cluster with Kmesh installed.
- **Tools**: `kubectl`, `tcpdump`, and `kmeshctl`.
- **Applications**: `echo` and `sleep` applications deployed in the cluster.

## Example YAML for Deployment

**Sleep Application (save as `sleep.yaml`):**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: sleep
  labels:
    app: sleep
spec:
  ports:
  - port: 80
    name: http
  selector:
    app: sleep
---
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
      nodeName: kmesh-testing-control-plane
      containers:
      - name: sleep
        image: curlimages/curl
        command: ["/bin/sleep", "infinity"]
```

**Echo Application (save as `echo.yaml`):**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: echo
spec:
  ports:
  - name: http
    port: 80
    targetPort: 8080
  selector:
    app: echo
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo
  template:
    metadata:
      labels:
        app: echo
    spec:
      containers:
      - name: echo
        image: gcr.io/istio-testing/app:latest
        args:
        - --port=8080
        ports:
        - containerPort: 8080
```

## IPSec E2E Tests

### 1. Basic Connectivity Test

This test verifies the establishment of IPSec tunnels and the correctness of encrypted communication.

#### Steps

1. Deploy the `sleep` and `echo` applications:

   ```bash
   kubectl apply -f sleep.yaml
   kubectl apply -f echo.yaml
   ```

2. Verify connectivity between the applications:

   ```bash
   kubectl exec <sleep-pod> -- curl http://<echo-service>
   ```

   **Expected Output:**

   ```plaintext
   Hello version: v1, instance: echo-<pod-id>
   ```

3. Check IPSec state:

   ```bash
   ip xfrm state show
   ```

   **Expected Output:**

   ```plaintext
   src {{SRC_IP}} dst {{DST_IP}}
       proto esp spi 0x{{SPI}} reqid 1 mode tunnel
       replay-window 0 
       output-mark 0xd0/0xffffffff
       aead rfc4106(gcm(aes)) {{KEY}} 128
       anti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000
       sel src ::/0 dst ::/0 
   ```

4. Check IPSec policy:

   ```bash
   ip xfrm policy show
   ```

   **Expected Output:**

   ```plaintext
   src ::/0 dst {{DST_SUBNET}} 
       dir out priority 0 
       mark 0xe0/0xffffffff 
       tmpl src {{SRC_IP}} dst {{DST_IP}}
           proto esp spi 0x{{SPI}} reqid 1 mode tunnel
   ```

5. Verify encryption using `tcpdump`:

   ```bash
   tcpdump -i any esp
   ```

   **Expected Output:** ESP packets should be visible during communication.

### 2. Key Rotation Test

This test ensures the reliability of the PSK update mechanism and validates service continuity during key changes.

#### Steps

1. Record the initial SPI:

   ```bash
   ip xfrm state show
   ```

   **Expected Output:**

   ```plaintext
   src {{SRC_IP}} dst {{DST_IP}}
       proto esp spi 0x{{INITIAL_SPI}} reqid 1 mode tunnel
       aead rfc4106(gcm(aes)) {{INITIAL_KEY}} 128
   ```

2. Send continuous traffic between the applications:

   ```bash
   kubectl exec <sleep-pod> -- curl http://<echo-service>
   ```

3. Update the pre-shared key:

   ```bash
   kmeshctl secret create --key=<new-key>
   ```

4. Verify that the SPI and key are updated in the xfrm rules:

   ```bash
   ip xfrm state show
   ```

   **Expected Output:**

   ```plaintext
   src {{SRC_IP}} dst {{DST_IP}}
       proto esp spi 0x{{INITIAL_SPI + 1}} reqid 1 mode tunnel
       aead rfc4106(gcm(aes)) {{NEW_KEY}} 128
   ```

5. Ensure communication continuity and encryption status.

## Offload Authorization E2E Tests

### Unified Steps for Authorization Tests

1. Apply the policy:

   ```bash
   kubectl apply -f <policy-file>.yaml
   ```

2. Test connectivity:

   ```bash
   kubectl exec <sleep-pod> -- curl http://<echo-service>
   ```

   **Expected Output:**

   - **ALLOW Policy:** The curl command should succeed, and the HTTP response code should be `200`.
   - **DENY Policy:** The curl command should fail, and no response should be received.

### Example Policies

#### IP Authorization Policy

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: ip-allow-policy
  namespace: test-ns1
spec:
  action: ALLOW
  rules:
  - from:
    - source:
        ipBlocks:
        - "{{ALLOWED_IP}}"
```

#### Port Authorization Policy

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: port-allow-policy
  namespace: test-ns1
spec:
  action: ALLOW
  rules:
  - to:
    - operation:
        ports: ["{{ALLOWED_PORT}}"]
```

#### Header Authorization Policy

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: header-allow-policy
  namespace: test-ns1
spec:
  action: ALLOW
  rules:
  - when:
    - key: request.headers["{{HEADER_NAME}}"]
      values: ["{{HEADER_VALUE}}"]
```

#### Namespace Authorization Policy

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: namespace-allow-policy
  namespace: test-ns1
spec:
  action: ALLOW
  rules:
  - from:
    - source:
        namespaces: ["{{SOURCE_NAMESPACE}}"]
```

#### Host Authorization Policy

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: host-allow-policy
  namespace: test-ns1
spec:
  action: ALLOW
  rules:
  - to:
    - operation:
        hosts: ["{{TARGET_HOST}}"]
```

## Cleanup

After completing the tests, clean up the resources:

```bash
kubectl delete -f sleep.yaml
kubectl delete -f echo.yaml
kubectl delete authorizationpolicy --all -n test-ns1
```
