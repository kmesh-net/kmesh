## kmeshctl secret

Use secrets to generate secret configuration data for IPsec

```bash
kmeshctl secret [flags]
```

### Examples

```bash
# Use secrets to generate secret configuration data for IPsec:
 kmeshctl secret --key or -k, only support use aead algo: rfc4106(gcm(aes))
 key need 36 characters(use 32 characters as key, 4 characters as salt).
 Hexadecimal dump is required when the key is entered.
 e.g.:kmeshctl secret --key=$(dd if=/dev/urandom count=36 bs=1 2>/dev/null | xxd -p -c 64)
 e.g.:kmeshctl secret -k=$(echo -n "{36-character user-defined key here}" | xxd -p -c 64)
```

### Options

```bash
  -h, --help         help for secret
  -k, --key string   key of the encryption
```

### SEE ALSO

* [kmeshctl](kmeshctl.md)	 - Kmesh command line tools to operate and debug Kmesh

