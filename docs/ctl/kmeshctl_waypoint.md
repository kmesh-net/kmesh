## kmeshctl waypoint

Manage waypoint configuration

### Synopsis

A group of commands used to manage waypoint configuration

```
kmeshctl waypoint [flags]
```

### Examples

```
  # Apply a waypoint to the current namespace
  kmeshctl waypoint apply

  # Generate a waypoint as yaml
  kmeshctl waypoint generate --namespace default

  # List all waypoints in a specific namespace
  kmeshctl waypoint list --namespace default
```

### Options

```
  -h, --help               help for waypoint
      --image string       image of the waypoint
      --name string        name of the waypoint (default "waypoint")
  -n, --namespace string   Kubernetes namespace
```

### SEE ALSO

* [kmeshctl](kmeshctl.md)	 - Kmesh command line tools to operate and debug Kmesh
* [kmeshctl waypoint apply](kmeshctl_waypoint_apply.md)	 - Apply a waypoint configuration
* [kmeshctl waypoint delete](kmeshctl_waypoint_delete.md)	 - Delete a waypoint configuration
* [kmeshctl waypoint generate](kmeshctl_waypoint_generate.md)	 - Generate a waypoint configuration
* [kmeshctl waypoint list](kmeshctl_waypoint_list.md)	 - List managed waypoint configurations
* [kmeshctl waypoint status](kmeshctl_waypoint_status.md)	 - Show the status of waypoints in a namespace

