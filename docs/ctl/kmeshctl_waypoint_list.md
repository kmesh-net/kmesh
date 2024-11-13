## kmeshctl waypoint list

List managed waypoint configurations

### Synopsis

List managed waypoint configurations in the cluster

```
kmeshctl waypoint list [flags]
```

### Examples

```
  # List all waypoints in a specific namespace
  kmeshctl waypoint list --namespace default

  # List all waypoints in the cluster
  kmeshctl waypoint list -A
```

### Options

```
  -A, --all-namespaces   List all waypoints in all namespaces
  -h, --help             help for list
```

### Options inherited from parent commands

```
      --image string       image of the waypoint
      --name string        name of the waypoint (default "waypoint")
  -n, --namespace string   Kubernetes namespace
```

### SEE ALSO

* [kmeshctl waypoint](kmeshctl_waypoint.md)	 - Manage waypoint configuration

