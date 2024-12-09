## kmeshctl monitoring

Control Kmesh's monitoring to be turned on as needed

```
kmeshctl monitoring [flags]
```

### Examples

```
# Enable/Disable Kmesh's accesslog:
kmeshctl monitoring <kmesh-daemon-pod> --accesslog enable/disable

# Enable/Disable services' metrics and accesslog generated from bpf:
kmeshctl monitoring <kmesh-daemon-pod> --all enable/disable

# Enable/Disable workload granularity metrics:
kmeshctl monitoring <kmesh-daemon-pod> --workloadMetrics enable/disable

# If you want to change the monitoring functionality of all kmesh daemons in the cluster
# Enable/Disable Kmesh's accesslog in each node:
kmeshctl monitoring --accesslog enable/disable

# Enable/Disable workload granularity metrics in each node:
kmeshctl monitoring --workloadMetrics enable/disable

#Enable/Disable services' and workloads' metrics and accesslog generated from bpf in each node:
kmeshctl monitoring --all enable/disable
```

### Options

```
      --accesslog string         Control accesslog enable or disable
      --all string               Control accesslog and services' and workloads' metrics enable or disable together
  -h, --help                     help for monitoring
      --workloadMetrics string   Control granularity metrics enable or disable
```

### SEE ALSO

* [kmeshctl](kmeshctl.md)	 - Kmesh command line tools to operate and debug Kmesh

