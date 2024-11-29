## kmeshctl authz

Enable or disable xdp authz eBPF Prog for Kmesh's authz offloading

```
kmeshctl authz [flags]
```

### Examples

```
# Enable/Disable Kmesh's authz offloading in the specified kmesh daemon:
 kmeshctl authz <kmesh-daemon-pod> enable/disable
 
 # If you want to enable or disable authz offloading of all Kmeshs in the cluster
 kmeshctl authz enable/disable
```

### Options

```
  -h, --help   help for authz
```

### SEE ALSO

* [kmeshctl](kmeshctl.md)	 - Kmesh command line tools to operate and debug Kmesh

