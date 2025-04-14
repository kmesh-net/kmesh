---
title: kmeshctl waypoint apply
sidebar_position: 2
---

Apply a waypoint configuration to the cluster

```bash
kmeshctl waypoint apply [flags]
```

### Examples
```bash
# Apply a waypoint to the current namespace
kmeshctl waypoint apply

# Apply a waypoint to a specific namespace and wait for it to be ready
kmeshctl waypoint apply --namespace default --wait

# Apply a waypoint to a specific pod
kmeshctl waypoint apply -n default --name reviews-v2-pod-waypoint --for workload
```

### Options
```bash
      --enroll-namespace   If set, the namespace will be labeled with the waypoint name
      --for string         Specify the traffic type [all none service workload] for the waypoint
  -h, --help               help for apply
      --overwrite          Overwrite the existing Waypoint used by the namespace
  -r, --revision string    The revision to label the waypoint with
  -w, --wait               Wait for the waypoint to be ready
```

### Options inherited from parent commands
```bash
      --image string       image of the waypoint
      --name string        name of the waypoint (default "waypoint")
  -n, --namespace string   Kubernetes namespace
```