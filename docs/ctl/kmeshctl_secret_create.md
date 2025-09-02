## kmeshctl secret create

Generate IPsec key and configuration by kmeshctl

```bash
kmeshctl secret create [flags]
```

### Examples

```bash
# Generate IPsec configuration with random IPsec key:: 
kmeshctl secret create
# Generate IPsec configuration with user-defined key:
kmeshctl secret create --key=$(echo -n "{36-character user-defined key here}" | xxd -p -c 64)"
```

### Options

```bash
  -h, --help         help for create
  -k, --key string   key of the encryption
```

### SEE ALSO

* [kmeshctl secret](kmeshctl_secret.md) - Use secrets to manage secret configuration data for IPsec
