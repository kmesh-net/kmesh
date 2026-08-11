## kmeshctl dump

Dump config of kernel-native or dual-engine mode

```bash
kmeshctl dump [kmesh-daemon-pod] <mode> [flags]
```

### Examples

```bash
# Kernel Native mode (table output) for a specific pod:
kmeshctl dump <kmesh-daemon-pod> kernel-native

# Kernel Native mode (table output) auto-detecting the pod:
kmeshctl dump kernel-native

# Dual Engine mode (table output) auto-detecting the pod:
kmeshctl dump dual-engine

# Output as raw JSON:
kmeshctl dump kernel-native -o json
```

### Options

```bash
  -h, --help            help for dump
  -o, --output string   Output format: table or json (default "table")
```

### SEE ALSO

* [kmeshctl](kmeshctl.md) - Kmesh command line tools to operate and debug Kmesh
