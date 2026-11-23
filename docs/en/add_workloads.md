# Adding Workloads to Kmesh

## How to Add Workloads

Kmesh manages pod traffic based on specific Kubernetes labels. Workloads can be enrolled by labeling either the namespace or the individual pod.

### Namespace Enrollment

To enable Kmesh for a specified namespace, apply the `istio.io/dataplane-mode` label with the value `kmesh`:

```shell
kubectl label namespace <namespace> istio.io/dataplane-mode=kmesh
```

To disable Kmesh for a specified namespace, remove the label:

```shell
kubectl label namespace <namespace> istio.io/dataplane-mode-
```

### Pod Enrollment

You can also enroll a pod by directly applying the `istio.io/dataplane-mode=kmesh` label to it.

```shell
kubectl label pod <pod-name> -n <namespace> istio.io/dataplane-mode=kmesh --overwrite
```

To explicitly disable Kmesh enrollment for a specific pod, set the label value to `none` (`istio.io/dataplane-mode=none`). This excludes the pod from being managed by Kmesh.

## Exclusions

Kmesh will not manage a pod if any of the following conditions are met:

* The pod has an Istio sidecar.
* The pod uses `hostNetwork`.
* The pod is an Istio managed waypoint proxy.

## Verification Methods

To verify that your workload has been successfully enrolled in Kmesh, use the following methods:

* **Annotation:** Successful enrollment adds the `kmesh.net/redirection: enabled` annotation to the pod.
* **CNI Plugin Logs:** Check the CNI plugin logs recorded in the `/var/run/kmesh` directory on the Kubernetes node.
* **Kmesh Daemon Logs:** Check the logs of the Kmesh daemon. First, get the pod name, and then view its logs:

```shell
kubectl get po -n kmesh-system
kubectl logs <kmesh-pod-name> -n kmesh-system
```
