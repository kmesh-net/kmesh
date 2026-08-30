## kmeshctl dnsproxy

Enable or disable Kmesh's DNS proxy

```bash
kmeshctl dnsproxy [pod] enable|disable [flags]
```

### Examples

```bash
# Enable Kmesh's DNS proxy:
kmeshctl dnsproxy <kmesh-daemon-pod> enable

# Disable Kmesh's DNS proxy:
kmeshctl dnsproxy <kmesh-daemon-pod> disable

# Enable/Disable DNS proxy on all kmesh daemons in the cluster:
kmeshctl dnsproxy enable
kmeshctl dnsproxy disable
```

### Options

```bash
  -h, --help   help for dnsproxy
```

### SEE ALSO

* [kmeshctl](kmeshctl.md) - Kmesh command line tools to operate and debug Kmesh
