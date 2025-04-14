---
title: kmeshctl waypoint list
sidebar_position: 5
---

List managed waypoint configurations in the cluster

```bash
kmeshctl waypoint list [flags]
```

### Examples
```bash
# List all waypoints in a specific namespace
kmeshctl waypoint list --namespace default

# List all waypoints in the cluster
kmeshctl waypoint list -A
```

### Options
```bash
  -A, --all-namespaces   List all waypoints in all namespaces
  -h, --help             help for list
```

### Options inherited from parent commands
```bash
      --image string       image of the waypoint
      --name string        name of the waypoint (default "waypoint")
  -n, --namespace string   Kubernetes namespace
```