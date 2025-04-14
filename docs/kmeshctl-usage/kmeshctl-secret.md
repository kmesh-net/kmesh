---
title: kmeshctl secret
sidebar_position: 6
---

Use secrets to generate secret configuration data for IPsec

```bash
kmeshctl secret [flags]
```

### Examples

```bash
# Use secrets to generate secret configuration data for IPsec:
 Use --key (or -k) with the AEAD algorithm rfc4106(gcm(aes)); the key must be 36 characters long (32 for key and 4 for salt).
	 A hexadecimal dump is required when the key is entered.
	 e.g.: kmeshctl secret --key=$(dd if=/dev/urandom count=36 bs=1 2>/dev/null | xxd -p -c 64)
	 e.g.: kmeshctl secret -k=$(echo -n "{36-character user-defined key here}" | xxd -p -c 64)
```

### Options

```bash
  -h, --help         help for secret
  -k, --key string   key of the encryption
```
