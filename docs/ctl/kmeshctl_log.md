## kmeshctl log

Get or set kmesh-daemon's logger level

```
kmeshctl log [flags]
```

### Examples

```
# Set default logger's level as "debug":
kmeshctl log <kmesh-daemon-pod> --set default:debug

# Get all loggers' name
kmeshctl log <kmesh-daemon-pod>
	  
# Get default logger's level:
kmeshctl log <kmesh-daemon-pod> default
```

### Options

```
  -h, --help         help for log
      --set string   Set the logger level (e.g., default:debug)
```

### SEE ALSO

* [kmeshctl](kmeshctl.md)	 - Kmesh command line tools to operate and debug Kmesh

