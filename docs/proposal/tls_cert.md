## Workload Certificate Management

### Overview

Kmesh requires certificates issued by Istiod to support TLS capabilities. Therefore, a certificate request and management module is needed to apply for certificates from Istiod and manage the lifecycle of the certificates.

### Motivation

Kmesh needs to provide TLS capabilities for managed workloads and needs to be able to conveniently apply for and manage certificates, adding, deleting, and refreshing certificates at the appropriate time.

#### Goals

1. Apply for certificates for the service account (sa) where the managed workload is located.
2. Automatically refresh the certificate when it expires.

#### Non-Goals

1. In ambient mode, ztunnel and Kmesh each have their own certificate management system, which do not interfere with each other. There may be situations where both have applied for certificates for a certain sa. In this case, whoever takes over the traffic will use their set of certificates.
2. In the event of an abnormal restart of Kmesh, all old certificate records are discarded and all certificates are re-applied. Retaining previous certificates is not considered.

### Proposal

Implement a certificate application module and a certificate management module, where:

Certificate Application Module: Establish an encrypted gRPC connection with Istiod when Kmesh starts, construct a CSR request and corresponding private key for the sa (service account) where the managed workload is located, and interact with Istiod using the CSR request. Istiod returns the certificate after signing.

Certificate Management Module:

- Manage the timing of operations on certificates: 1. Add workload 2. Delete workload 3. Automatically refresh the certificate when it expires.
- Manage the storage and management method of the certificate.
- Trigger the corresponding certificate refresh task when the certificate is about to expire.

### Limitations

Currently, if you need to use Kmesh tls capabilities, you need to modify the deployment when Istio starts, and add `kmesh-system/kmesh` after the `CA_TRUSTED_NODE_ACCOUNTS` environment variable.

## Design Details

### Certificate Application Module

Create a caclient client when Kmesh starts, and establish an encrypted gRPC connection with Istiod.

Use the information in the workload to construct a CSR request and private key, send the CSR request to Istiod through caclient, and Istiod returns the certificate after signing.

### Certificate Lifecycle Management

Use a channel, queue, and map to record and manage, where the queue and map both have locks to ensure concurrency safety.

<div align="center">

![tls_cert_design](pics/tls_cert_design.svg)

</div>

**Channel**: Manage certificate events, handle certificate tasks according to Operation, create tasks in order from the channel, which can prevent some concurrent scheduling problems.

```go
chan: used to receive all certificate-related events
type certRequest struct {
	Identity  string
	Operation int
}
```

Trigger timing:

- When adding a workload
- When deleting a workload
- When the certificate expires, take out the certificate refresh task from the queue

**Queue**: Check the certificate that is about to expire, refresh the certificate 1 hour in advance;

```go
Queue element content:
type certExp struct {
    identity string	//The certificate name constructed using sa
    exp time.Time	//Certificate expiration time
}
```

Update timing: Add a certificate: insert a new record Refresh the certificate: delete the old record, add a new record; Delete the certificate: traverse and delete the old certificate record

**Map**: Record certificate information and certificate status

```go
map: record the number of pods using this certificate
	key: Identity    //The certificate name constructed using sa
	value: certItem

type certItem struct {
	cert istiosecurity.SecretItem    //Certificate information
    refcnt int32     //Record the number of pods using this certificate
}
```

Update timing: When a pod is managed by Kmesh for the first time under a certain sa, a new certificate is added; a new record is created and added When all pods managed by Kmesh under this sa are deleted (refCnt=0), delete the certificate; delete a record

 When the certificate expires automatically refresh, update the value content; refresh the cert in the existing record

 When a pod is managed by Kmesh under a certain sa, the corresponding refcnt+1； When a pod managed by Kmesh under a certain sa is deleted, the corresponding refcnt-1；

Lifecycle: The time when the certificate of the entire sa exists; created at the time of sa certificate application, deleted at the time of sa certificate deletion

#### Scenario One: Add Certificate

<div align="center">

![tls_cert_scenario1](pics/tls_cert_scenario1.svg)

</div>

1. Kmesh manages pod1, subscribes to the added workload, SecretManager looks for the corresponding sa certificate: if it already exists, count +1; if it does not exist, apply for a certificate
2. Construct and send a CSR request for sa1
3. Istiod issues a certificate
4. Store the certificate:
   - Store the certificate
   - In the status information
     - Record count, count for this sa, record the number of pods using this certificate；
   - Add a record of the expiration time to the queue

#### Scenario Two: Delete Certificate

<div align="center">

![tls_cert_scenario2](pics/tls_cert_scenario2.svg)

</div>

1. Delete pod1, delete the corresponding workload

2. The count of this sa is reduced by one；

    

   If the count of this sa is 0 at this time, delete the certificate：

   - Traverse and find the queue, delete the corresponding record
   - Delete the certificate corresponding to sa

#### Scenario Three: Certificate Expires Automatically Update

<div align="center">

![tls_cert_scenario3](pics/tls_cert_scenario3.svg)

</div>

1. The certificate with the nearest expiration date in the queue expires, pop up this record, trigger the certificate refresh action
2. Construct and send a CSR request for the sa of this certificate
3. Istiod issues a certificate
4. Store the certificate,
   - Refresh the certificate in the map; refcnt remains unchanged

- Add this record to the queue

#### Special Design:

The map and queue both use locks to ensure concurrency safety, all operations involving the map and queue use the defined interface to avoid deadlock and other problems

Since applying for a certificate requires interaction with Istiod through a grpc connection, which may take a long time, and the change of certificate status information has added a lock for concurrency safety, so when you need to add or refresh a certificate, you need to separate the change of certificate status information and the process of applying for a certificate:

For example: in the function flow of adding a certificate, if it is judged that a new certificate needs to be applied for, it will first create the corresponding status information record and write it into the map, so that other threads will not apply for the certificate repeatedly when executing, and then write into this record after the certificate is refreshed, if the application fails, delete this record;

### Remaining Issues

1. The current implementation of the queue is a priority queue. It needs to be modified to a normal queue. In the current scenario, the certificate events are obtained from the channel in order, and the certificate applied by Kmesh for the workload has a consistent validity period, so there is no need to sort in the queue again
2. Managed pod judgment, the current Kmesh related certificate processing process cannot judge whether the workload is managed, to be implemented later
3. There is only one pod under a certain sa, the pod restarts, causing the workload to be quickly deleted and added, and the certificate will be added and deleted repeatedly, bringing unnecessary overhead, this scenario needs special treatment