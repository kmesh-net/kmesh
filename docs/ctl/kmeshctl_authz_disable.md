## kmeshctl authz disable

Disable xdp authz eBPF program for Kmesh's authz offloading

```bash
kmeshctl authz disable [podNames...] [flags]
```

### Examples

```bash
kmeshctl authz disable
kmeshctl authz disable pod1 pod2
```

### Options

```bash
  -h, --help   help for disable
```

### Options inherited from parent commands

```bash
      --kmesh-namespace string   Namespace where Kmesh is installed (default "kmesh-system")
```

### SEE ALSO

* [kmeshctl authz](kmeshctl_authz.md) - Manage xdp authz eBPF program for Kmesh's authz offloading
