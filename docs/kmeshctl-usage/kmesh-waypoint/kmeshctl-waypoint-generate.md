---
title: kmeshctl waypoint generate
sidebar_position: 4
---

Generate a waypoint configuration as YAML

```bash
kmeshctl waypoint generate [flags]
```

### Examples
```bash
# Generate a waypoint as yaml
kmeshctl waypoint generate --namespace default

# Generate a waypoint that can process traffic for service in default namespace
kmeshctl waypoint generate --for service -n default
```

### Options
```bash
      --for string        Specify the traffic type [all none service workload] for the waypoint
  -h, --help              help for generate
  -r, --revision string   The revision to label the waypoint with
```

### Options inherited from parent commands
```bash
      --image string       image of the waypoint
      --name string        name of the waypoint (default "waypoint")
  -n, --namespace string   Kubernetes namespace
```