---
title: Configuration
sidebar_position: 1
---

Manage waypoint configuration

### Synopsis

A group of commands used to manage waypoint configuration

```bash
kmeshctl waypoint [flags]
```

### Examples

```bash
  # Apply a waypoint to the current namespace
  kmeshctl waypoint apply

  # Generate a waypoint as yaml
  kmeshctl waypoint generate --namespace default

  # List all waypoints in a specific namespace
  kmeshctl waypoint list --namespace default
```

### Options

```bash
  -h, --help               help for waypoint
      --image string       image of the waypoint
      --name string        name of the waypoint (default "waypoint")
  -n, --namespace string   Kubernetes namespace
```
