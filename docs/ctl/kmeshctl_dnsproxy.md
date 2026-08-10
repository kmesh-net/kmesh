## kmeshctl dnsproxy

Control Kmesh's DNS proxy to be enabled or disabled at runtime

### Examples

```bash
# Enable DNS proxy for a specific kmesh daemon pod:
kmeshctl dnsproxy <kmesh-daemon-pod> enable

# Disable DNS proxy for a specific kmesh daemon pod:
kmeshctl dnsproxy <kmesh-daemon-pod> disable

# Check DNS proxy status for a specific kmesh daemon pod:
kmeshctl dnsproxy <kmesh-daemon-pod> status

# Enable DNS proxy for all kmesh daemon pods:
kmeshctl dnsproxy enable

# Disable DNS proxy for all kmesh daemon pods:
kmeshctl dnsproxy disable

# Check DNS proxy status for all kmesh daemon pods:
kmeshctl dnsproxy status
```

### Options

```bash
  -h, --help   help for dnsproxy
```

### SEE ALSO

* [kmeshctl](kmeshctl.md) - Kmesh command line tools to operate and debug Kmesh
