## kmeshctl waypoint status

Show the status of waypoints in a namespace

### Synopsis

Show the status of waypoints for the namespace provided or default namespace if none is provided

```
kmeshctl waypoint status [flags]
```

### Examples

```
  # Show the status of the waypoint in the default namespace
  kmeshctl waypoint status

  # Show the status of the waypoint in a specific namespace
  kmeshctl waypoint status --namespace foo
```

### Options

```
  -h, --help   help for status
```

### Options inherited from parent commands

```
      --image string       image of the waypoint
      --name string        name of the waypoint (default "waypoint")
  -n, --namespace string   Kubernetes namespace
```

### SEE ALSO

* [kmeshctl waypoint](kmeshctl_waypoint.md)	 - Manage waypoint configuration

