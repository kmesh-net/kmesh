## kmeshctl waypoint generate

Generate a waypoint configuration

### Synopsis

Generate a waypoint configuration as YAML

```
kmeshctl waypoint generate [flags]
```

### Examples

```
  # Generate a waypoint as yaml
  kmeshctl waypoint generate --namespace default

  # Generate a waypoint that can process traffic for service in default namespace
  kmeshctl waypoint generate --for service -n default
```

### Options

```
      --for string        Specify the traffic type [all none service workload] for the waypoint
  -h, --help              help for generate
  -r, --revision string   The revision to label the waypoint with
```

### Options inherited from parent commands

```
      --image string       image of the waypoint
      --name string        name of the waypoint (default "waypoint")
  -n, --namespace string   Kubernetes namespace
```

### SEE ALSO

* [kmeshctl waypoint](kmeshctl_waypoint.md)	 - Manage waypoint configuration

