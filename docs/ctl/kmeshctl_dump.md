## kmeshctl dump

Dump config of kernel-native or dual-engine mode

```bash
kmeshctl dump [flags]
```

### Examples

```bash
# Kernel Native mode (table output):
kmeshctl dump <kmesh-daemon-pod> kernel-native

# Dual Engine mode (table output):
kmeshctl dump <kmesh-daemon-pod> dual-engine

# Output as raw JSON:
kmeshctl dump <kmesh-daemon-pod> kernel-native -o json
```

### Options

```bash
  -h, --help            help for dump
  -o, --output string   Output format: table or json (default "table")
```

### SEE ALSO

* [kmeshctl](kmeshctl.md) - Kmesh command line tools to operate and debug Kmesh
