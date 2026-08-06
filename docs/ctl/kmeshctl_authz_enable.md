## kmeshctl authz enable

Enable xdp authz eBPF program for Kmesh's authz offloading

```bash
kmeshctl authz enable [podNames...] [flags]
```

### Examples

```bash
kmeshctl authz enable
kmeshctl authz enable pod1 pod2
```

### Options

```bash
  -h, --help   help for enable
```

### Options inherited from parent commands

```bash
      --kmesh-namespace string   Namespace where Kmesh is installed (default "kmesh-system")
```

### SEE ALSO

* [kmeshctl authz](kmeshctl_authz.md) - Manage xdp authz eBPF program for Kmesh's authz offloading
