## kmeshctl monitoring

Control Kmesh's monitoring to be turned on as needed

```
kmeshctl monitoring [flags]
```

### Examples

```
# Enable/Disable Kmesh's accesslog:
kmeshctl monitoring <kmesh-daemon-pod> --accesslog enable/disable

# Enable/Disable Kmesh's metrics and accesslog:
kmeshctl monitoring <kmesh-daemon-pod> --all enable/disable

# If you want to change the monitoring functionality of all kmesh daemons in the cluster
kmeshctl monitoring --accesslog enable/disable
kmeshcrl monitoring --all enable/disable
```

### Options

```
      --accesslog string   Control accesslog enable or disable
      --all string         Control accesslog and metrics enable or disable together
  -h, --help               help for monitoring
```

### SEE ALSO

* [kmeshctl](kmeshctl.md)	 - Kmesh command line tools to operate and debug Kmesh

