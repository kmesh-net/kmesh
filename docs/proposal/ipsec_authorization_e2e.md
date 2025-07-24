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

3. The fault recovery test simulates node restart scenarios and checks automatic recovery of IPSec functionality.

For the Offload Authorization feature, E2E test cases are designed for IP, Port, Header, namespace, and hosts authorization.

The test environment requires at least a 2-node Kubernetes cluster using httpbin and sleep or fortio as test applications.

### Design Details

#### 1. Test Environment Preparation


##### Requirements

- At least a 2-node Kubernetes cluster with Kmesh installed  
- Tools: tcpdump  
- Applications: httpbin, sleep, fortio


#### 2. IPSec Test Scenarios

##### 2.1 Basic Connectivity E2E Test

###### Test Steps
- Deploy httpbin and sleep applications on different nodes  
- Verify connectivity between applications  
- Check IPSec state and policy rules 
   ```
   ip xfrm state show
   ip xfrm policy show
   ```
- Verify encryption using tcpdump; analyze ESP headers and confirm payload is encrypted
   ```
   tcpdump -i any esp
   ```
- Increase traffic volume to validate data integrity after encryption/decryption


##### 2.2 Key Rotation E2E Test

###### Test Steps

- Deploy httpbin and sleep applications on different nodes
- Record initial SPI and pre-shared key
   ```
   ip xfrm state show
   kubectl get secret
   ```

- Send continuous traffic between applications
- Update the pre-shared key
   ```
   kubectl create secret
   ```
- Check if SPI and key are updated
- Verify communication continuity, encryption status, and data integrity


##### 2.3 Fault Recovery E2E Test

###### Test Steps

- Deploy httpbin and sleep applications on different nodes
- Record the initial IPSec state
- Simulate node restart
   ```
   kubectl drain node1
   kubectl uncordon node1
   ```
-  Check if IPSec recovers automatically
   ```
   watch -n 1 'ip xfrm state show'
   ```
-  Verify if encrypted communication between applications is restored


#### 3. Offload Authorization Test Scenarios
Apply the corresponding security policies (ALLOW/DENY) and routing strategies, and verify connectivity. Tests can be conducted at workload, namespace, and global scopes.
##### 3.1  IP Authorization Test
- Example security policy YAML:
```
apiVersion: security.istio.io/v1
kind: Authorization
metadata:
  name: ip-allow-policy
  namespace: test-ns1
spec:
  action: ALLOW
  rules:
  - clauses:
    - matches:
      - sourceIps:
        - address: "192.168.1.0"
          length: 24
      - destinationIps:
        - address: "10.0.0.0"
          length: 16
---
apiVersion: security.istio.io/v1
kind: Authorization
metadata:
  name: ip-deny-policy
  namespace: test-ns1
spec:
  action: DENY
  rules:
  - clauses:
    - matches:
      - notSourceIps:
        - address: "172.16.0.0"
          length: 16
      - notDestinationIps:
        - address: "192.168.0.0"
          length: 16
```
##### 3.2 Port Authorization Test

```
apiVersion: security.istio.io/v1
kind: Authorization
metadata:
  name: port-allow-policy
  namespace: test-ns1
spec:
  action: ALLOW
  rules:
  - clauses:
    - matches:
      - destinationPorts: [8000, 9000]
---
apiVersion: security.istio.io/v1
kind: Authorization
metadata:
  name: port-deny-policy
  namespace: test-ns1
spec:
  action: DENY
  rules:
  - clauses:
    - matches:
      - notDestinationPorts: [7000, 7001]
```
##### 3.3 Namespace Authorization Test

```
apiVersion: security.istio.io/v1
kind: Authorization
metadata:
  name: namespace-allow-policy
  namespace: test-ns1
spec:
  action: ALLOW
  rules:
  - clauses:
    - matches:
      - namespaces:
        - exact: "test-ns1"
        - prefix: "prod-"
---
apiVersion: security.istio.io/v1
kind: Authorization
metadata:
  name: namespace-deny-policy
  namespace: test-ns1
spec:
  action: DENY
  rules:
  - clauses:
    - matches:
      - notNamespaces:
        - exact: "blocked-ns"
        - prefix: "test-"
```
##### 3.4 ServiceAccount Authorization Test

```
apiVersion: security.istio.io/v1
kind: Authorization
metadata:
  name: sa-allow-policy
  namespace: test-ns1
spec:
  action: ALLOW
  rules:
  - clauses:
    - matches:
      - principals:
        - exact: "cluster.local/ns/default/sa/httpbin"
        - prefix: "cluster.local/ns/test-"
---
apiVersion: security.istio.io/v1
kind: Authorization
metadata:
  name: sa-deny-policy
  namespace: test-ns1
spec:
  action: DENY
  rules:
  - clauses:
    - matches:
      - notPrincipals:
        - exact: "cluster.local/ns/blocked/sa/sleep"
        - suffix: "blocked-service"
```
##### 3.5 Header Authorization Test

```
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: header-allow-route
  namespace: test-ns1
spec:
  hosts:
  - "httpbin.test-ns1.svc.cluster.local"
  http:
  - match:
    - headers:
        x-custom-token:
          exact: "valid-token"
        user-agent:
          prefix: "test-client"
    route:
    - destination:
        host: httpbin
```
##### 3.6 Hosts Authorization Test

```
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: host-allow-route
  namespace: test-ns1
spec:
  hosts:
  - "httpbin.test-ns1.svc.cluster.local"
  - "httpbin.example.com"
  http:
  - route:
    - destination:
        host: httpbin
```

