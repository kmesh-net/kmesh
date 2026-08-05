## kmeshctl log

Get or set kmesh-daemon's logger level

```bash
kmeshctl log [podName] [loggerName] [flags]
```

### Examples

```bash
# Set default logger's level as "debug" for all/detected kmesh-daemon pod(s):
kmeshctl log --set default:debug

# Set default logger's level as "debug" for a specific pod:
kmeshctl log <kmesh-daemon-pod> --set default:debug

# Get all loggers' names for all/detected kmesh-daemon pod(s):
kmeshctl log

# Get all loggers' names for a specific pod:
kmeshctl log <kmesh-daemon-pod>

# Get default logger's level for all/detected kmesh-daemon pod(s):
kmeshctl log default

# Get default logger's level for a specific pod:
kmeshctl log <kmesh-daemon-pod> default
```

### Options

```bash
  -h, --help         help for log
      --set string   Set the logger level (e.g., default:debug)
```

### SEE ALSO

* [kmeshctl](kmeshctl.md) - Kmesh command line tools to operate and debug Kmesh
