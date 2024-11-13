## kmeshctl waypoint delete

Delete a waypoint configuration

### Synopsis

Delete a waypoint configuration from the cluster

```
kmeshctl waypoint delete [flags]
```

### Examples

```
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

```
      --all    Delete all waypoints in the namespace
  -h, --help   help for delete
```

### Options inherited from parent commands

```
      --image string       image of the waypoint
      --name string        name of the waypoint (default "waypoint")
  -n, --namespace string   Kubernetes namespace
```

### SEE ALSO

* [kmeshctl waypoint](kmeshctl_waypoint.md)	 - Manage waypoint configuration

