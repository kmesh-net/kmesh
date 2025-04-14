---
title: Kmeshctl Log
sidebar_position: 5
---

Get or set kmesh-daemon's logger level

```bash
kmeshctl log [flags]
```

### Examples
```bash
# Set default logger's level as "debug":
kmeshctl log <kmesh-daemon-pod> --set default:debug

# Get all loggers' name
kmeshctl log <kmesh-daemon-pod>
	  
# Get default logger's level:
kmeshctl log <kmesh-daemon-pod> default
```

### Options
```bash
  -h, --help         help for log
      --set string   Set the logger level (e.g., default:debug)
```