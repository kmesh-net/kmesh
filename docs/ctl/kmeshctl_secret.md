## kmeshctl secret

Manage IPsec secrets for Kmesh

### Synopsis

Manage secret configuration data for IPsec encryption.
This command provides functionality to create, retrieve, and delete
IPsec keys and configurations stored as Kubernetes secrets.

```bash
kmeshctl secret [command]
```

### Examples

```bash
# Create a new IPsec secret with automatically generated key
kmeshctl secret create

# Create an IPsec secret with user-defined key
kmeshctl secret create --key=$(echo -n "{36-character user-defined key here}" | xxd -p -c 64)

# Get IPsec key and configuration
kmeshctl secret get

# Delete IPsec key and configuration
kmeshctl secret delete
```

### Options

```bash
  -h, --help   help for secret
```

### SEE ALSO

* [kmeshctl](kmeshctl.md) - Kmesh command line tools to operate and debug Kmesh
* [kmeshctl secret create](kmeshctl_secret_create.md) - Generate IPsec key and configuration by kmeshctl
* [kmeshctl secret get](kmeshctl_secret_get.md) - Get IPsec key and configuration by kmeshctl
* [kmeshctl secret delete](kmeshctl_secret_delete.md) - Delete IPsec key and configuration by kmeshctl
