## kmeshctl secret create

Generate IPsec key and configuration by kmeshctl

### Synopsis

Generate IPsec key and configuration using either automatically generated 
cryptographically secure random bytes or a user-defined key. The key is 
formatted for use with the rfc4106(gcm(aes)) AEAD algorithm and stored 
as a Kubernetes secret.

```bash
kmeshctl secret create [flags]
```

### Examples

```bash
# Generate IPsec configuration with random IPsec key
kmeshctl secret create

# Generate IPsec configuration with user-defined key
# Note: The key must be exactly 36 characters (36 bytes)
kmeshctl secret create --key=$(echo -n "{36-character user-defined key here}" | xxd -p -c 64)

```

### Options

```bash
  -h, --help         help for create
  -k, --key string   key of the encryption (36-byte key as hex string)
```

### Details

- The IPsec key consists of 32 bytes for the AES-256 key and 4 bytes for the salt value
- If no key is provided, a cryptographically secure random key is generated
- The secret is stored in the `kmesh-system` namespace with the name `kmesh-ipsec`
- If a secret already exists, it will be updated with a new SPI (Security Parameter Index)

### SEE ALSO

* [kmeshctl secret](kmeshctl_secret.md) - Manage IPsec secrets for Kmesh
