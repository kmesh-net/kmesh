## kmeshctl version

Prints out build version info

```bash
kmeshctl version [flags]
```

### Examples

```bash
# Show version of all kmesh components
kmeshctl version

# Show version info of a specific kmesh daemon
kmeshctl version <kmesh-daemon-pod>
```

### Options

```bash
  -h, --help   help for version
```

### Options inherited from parent commands

```bash
      --kmesh-namespace string   Namespace where Kmesh is installed (default "kmesh-system")
```

### SEE ALSO

* [kmeshctl](kmeshctl.md) - Kmesh command line tools to operate and debug Kmesh
