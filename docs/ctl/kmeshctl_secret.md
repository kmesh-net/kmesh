## kmeshctl secret

Use secrets to generate secret configuration data for IPsec

```
kmeshctl secret [flags]
```

### Examples

```
# Use secrets to generate secret configuration data for IPsec:
 kmeshctl secret aeadKey aeadLength, only support rfc4106(gcm(aes))
```

### Options

```
  -h, --help            help for secret
  -l, --icvlength int   length of integrity check value
  -k, --key string      key of the encryption
```

### SEE ALSO

* [kmeshctl](kmeshctl.md)	 - Kmesh command line tools to operate and debug Kmesh

