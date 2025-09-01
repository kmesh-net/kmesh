## kmeshctl secret delete

Delete IPsec key and configuration by kmeshctl

### Synopsis

Delete the IPsec secret from the Kubernetes cluster. This removes the 
`kmesh-ipsec` secret from the `kmesh-system` namespace.

```bash
kmeshctl secret delete
```

### Examples

```bash
# Delete IPsec key and configuration
kmeshctl secret delete
```

### Options

```bash
  -h, --help   help for delete
```

### SEE ALSO

* [kmeshctl secret](kmeshctl_secret.md) - Manage IPsec secrets for Kmesh
* [kmeshctl secret create](kmeshctl_secret_create.md) - Generate IPsec key and configuration by kmeshctl
