## kmeshctl secret create

Create a new IPsec secret with automatically generated key

### Synopsis

Create a new IPsec secret with automatically generated encryption key.
The key is generated using cryptographically secure random bytes and formatted
for use with the rfc4106(gcm(aes)) AEAD algorithm.

```bash
kmeshctl secret create [flags]
```

### Examples

```bash
# Create a new IPsec secret with automatically generated key:
kmeshctl secret create

# This will generate a 36-byte key (32-byte key + 4-byte salt) and create
# the 'kmesh-ipsec' secret in the kmesh-system namespace.
```

### Options

```bash
  -h, --help   help for create
```

### SEE ALSO

* [kmeshctl secret](kmeshctl_secret.md) - Manage IPsec secrets for Kmesh
