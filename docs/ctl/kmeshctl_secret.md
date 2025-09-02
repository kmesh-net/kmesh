## kmeshctl secret

Use secrets to manage secret configuration data for IPsec

```bash
kmeshctl secret [flags]
```

### Examples

```bash
# Use kmeshctl secret to manage secret configuration data for IPsec:
kmeshctl secret create or kmeshctl secret create --key=$(echo -n "{36-character user-defined key here}" | xxd -p -c 64)
kmeshctl secret get
kmeshctl secret delete

```

### Options

```bash
  -h, --help   help for secret
```

### SEE ALSO

* [kmeshctl](kmeshctl.md) - Kmesh command line tools to operate and debug Kmesh
* [kmeshctl secret create](kmeshctl_secret_create.md) - Generate IPsec key and configuration by kmeshctl
* [kmeshctl secret delete](kmeshctl_secret_delete.md) - Delete IPsec key and configuration by kmeshctl
* [kmeshctl secret get](kmeshctl_secret_get.md) - Get IPsec key and configuration by kmeshctl
