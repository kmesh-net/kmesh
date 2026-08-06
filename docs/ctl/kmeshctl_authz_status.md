## kmeshctl authz status

Display the current authorization status

```bash
kmeshctl authz status [podNames...] [flags]
```

### Examples

```bash
kmeshctl authz status
kmeshctl authz status pod1 pod2
```

### Options

```bash
  -h, --help   help for status
```

### Options inherited from parent commands

```bash
      --kmesh-namespace string   Namespace where Kmesh is installed (default "kmesh-system")
```

### SEE ALSO

* [kmeshctl authz](kmeshctl_authz.md) - Manage xdp authz eBPF program for Kmesh's authz offloading
