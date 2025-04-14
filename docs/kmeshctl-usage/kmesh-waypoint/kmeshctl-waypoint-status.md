---
title: kmeshctl waypoint status
sidebar_position: 6
---

Show the status of waypoints for the namespace provided or default namespace if none is provided

```bash
kmeshctl waypoint status [flags]
```

### Examples
```bash
# Show the status of the waypoint in the default namespace
kmeshctl waypoint status

# Show the status of the waypoint in a specific namespace
kmeshctl waypoint status --namespace default
```

### Options
```bash
  -h, --help   help for status
```

### Options inherited from parent commands
```bash
      --image string       image of the waypoint
      --name string        name of the waypoint (default "waypoint")
  -n, --namespace string   Kubernetes namespace
```