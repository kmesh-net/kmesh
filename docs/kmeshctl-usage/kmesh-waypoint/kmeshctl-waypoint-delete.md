---
title: kmeshctl waypoint delete
sidebar_position: 3
---

Delete a waypoint configuration from the cluster

```bash
kmeshctl waypoint delete [flags]
```

### Examples
```bash
# Delete a waypoint from the default namespace
kmeshctl waypoint delete

# Delete a waypoint by name, which can obtain from kmeshctl waypoint list
kmeshctl waypoint delete waypoint-name --namespace default

# Delete several waypoints by name
kmeshctl waypoint delete waypoint-name1 waypoint-name2 --namespace default

# Delete all waypoints in a specific namespace
kmeshctl waypoint delete --all --namespace default
```

### Options
```bash
      --all    Delete all waypoints in the namespace
  -h, --help   help for delete
```

### Options inherited from parent commands
```bash
      --image string       image of the waypoint
      --name string        name of the waypoint (default "waypoint")
  -n, --namespace string   Kubernetes namespace
```