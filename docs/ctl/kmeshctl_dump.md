## kmeshctl dump

Dump config of ads-v1 or ads-v2 mode

```bash
kmeshctl dump [flags]
```

### Examples

```bash
# Ads-v1 mode (table output):
kmeshctl dump <kmesh-daemon-pod> ads-v1

# Ads-v2 mode (table output):
kmeshctl dump <kmesh-daemon-pod> ads-v2

# Output as raw JSON:
kmeshctl dump <kmesh-daemon-pod> ads-v1 -o json
```

### Options

```bash
  -h, --help            help for dump
  -o, --output string   Output format: table or json (default "table")
```

### SEE ALSO

* [kmeshctl](kmeshctl.md) - Kmesh command line tools to operate and debug Kmesh
