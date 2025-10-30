---
title: IPSec & Offload Authorization E2E Test
authors:
- "@xiaojiangao123" # Authors' GitHub accounts here.
reviewers:
- "@robot"
- TBD
approvers:
- "@robot"
- TBD

creation-date: 2025-5-12

---

## IPSec & Offload Authorization E2E Test Proposal

### Overview

This proposal aims to design end-to-end (E2E) test cases for the IPSec feature and Offload Authorization of Kmesh. The IPSec E2E tests focus on basic functionality, security, and reliability, verifying proper execution of IPSec tunnel setup, encryption/decryption, key management, and fault recovery. The Offload Authorization E2E tests include IP authorization, Port authorization, Header authorization, namespace authorization, and hosts authorization.

### Motivation

Kmesh’s IPSec functionality is a key component for secure communication within the service mesh. Its stability and reliability directly affect the security of the entire mesh. The Offload Authorization feature is a unique Kmesh capability that offloads IP and Port authorization to the Linux kernel via XDP. Without comprehensive E2E testing, version upgrades and releases may pose potential risks.

#### Goals

1. Develop complete E2E test cases  
2. Cover all functional scenarios of Kmesh IPSec  
3. Cover all types of Offload Authorization mechanisms

### Proposal

For the IPSec feature, we designed IPSec E2E test cases covering three core scenarios: basic connectivity, key rotation, and fault recovery.

1. The basic connectivity test verifies IPSec tunnel establishment and the correctness of encrypted communication using tcpdump to inspect ESP packets.

2. The key rotation test ensures the reliability of the PSK update mechanism and validates service continuity during key changes.

For the Offload Authorization feature, E2E test cases are designed for IP, Port, Header, Namespace, and Hosts authorization.

The test environment requires at least a 2-nodes Kubernetes cluster using httpbin and sleep or fortio as test applications.

### Design Details

#### 1. Test Environment Preparation

##### Requirements

- At least a 2-nodes Kubernetes cluster with Kmesh installed  
- Tools: tcpdump  
- Applications: httpbin, sleep, fortio

#### 2. IPSec Test Scenarios

##### 2.1 Basic Connectivity E2E Test

###### Test Steps

- Deploy httpbin and sleep applications on different nodes  
- Verify connectivity between applications  
- Check IPSec state and policy rules:

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

- Verify encryption using tcpdump; analyze ESP headers and confirm payload is encrypted:

   ```bash
   tcpdump -i any esp
   ```

   **Expected Output:** ESP packets should be visible during communication.

##### 2.2 Key Rotation E2E Test

###### Test Steps

- Deploy httpbin and sleep applications on different nodes
- Record initial SPI and pre-shared key:

   ```bash
   ip xfrm state show
   ```

   **Expected Output:**

   ```plaintext
   src {{SRC_IP}} dst {{DST_IP}}
       proto esp spi 0x{{INITIAL_SPI}} reqid 1 mode tunnel
       aead rfc4106(gcm(aes)) {{INITIAL_KEY}} 128
   ```

- Send continuous traffic between applications
- Update the pre-shared key

   ```bash
   kubectl create secret
   ```

- Check if SPI and key are updated in xfrm rules:

   ```bash
   ip xfrm state show
   ```

   **Expected Output:**

   ```plaintext
   src {{SRC_IP}} dst {{DST_IP}}
       proto esp spi 0x{{NEW_SPI}} reqid 1 mode tunnel
       aead rfc4106(gcm(aes)) {{NEW_KEY}} 128
   ```

- Verify communication continuity, encryption status

#### 3. Offload Authorization Test Scenarios

Apply the corresponding security policies (ALLOW/DENY) and routing strategies, and verify connectivity, including traffic that matches the rules and will be allowed and traffic that will be denied by the rules.

Here are some AuthorizationPolicy samples.

##### 3.1  IP Authorization Test

- Example security policy YAML:

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
        - "{{.Ip}}"
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: ip-deny-policy
  namespace: test-ns1
spec:
  action: DENY
  rules:
  - from:
    - source:
        ipBlocks:
        - "{{.Ip}}"
```

##### 3.2 Port Authorization Test

- Example security policy YAML:

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
        ports: {{.Ports}}
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: port-deny-policy
  namespace: test-ns1
spec:
  action: DENY
  rules:
  - to:
    - operation:
        ports: {{.Ports}}
```

##### 3.3 Namespace Authorization Test

- Example security policy YAML:

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
        namespaces:
        - "{{.SourceNamespace}}"
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: namespace-deny-policy
  namespace: test-ns1
spec:
  action: DENY
  rules:
  - from:
    - source:
        namespaces:
        - "{{.SourceNamespace}}"
```

##### 3.4 Header Authorization Test

- Example security policy YAML:

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
    - key: request.headers[{{.HeaderName}}]
      values: ["{{.HeaderValue}}"]
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: header-deny-policy
  namespace: test-ns1
spec:
  action: DENY
  rules:
  - when:
    - key: request.headers[{{.HeaderName}}]
      values: ["{{.HeaderValue}}"]
```

##### 3.5 Hosts Authorization Test

- Example security policy YAML:

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
        hosts: ["{{.TargetHost}}"]
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: host-deny-policy
  namespace: test-ns1
spec:
  action: DENY
  rules:
  - to:
    - operation:
        hosts: ["{{.TargetHost}}"]
```
