## kmeshctl secret get

Get IPsec key and configuration by kmeshctl

### Synopsis

Retrieve and display the current IPsec key and configuration from the 
Kubernetes secret. The output shows the secret metadata and IPsec 
configuration in a human-readable JSON format with the encryption key 
displayed as a hexadecimal string.

```bash
kmeshctl secret get
```

### Examples

```bash
# Get IPsec key and configuration
kmeshctl secret get
```

### Sample Output

```bash
Secret name: kmesh-ipsec
Namespace: kmesh-system
Created: 2025-08-28 15:28:05
IPsec Configuration:
{
  "spi": 1,
  "aeadKeyName": "rfc4106(gcm(aes))",
  "aeadKey": "48c8a522f7a14f21c9a175dd249b8f253f8f4950b105d959e610c8869db3e5c368909d18",
  "length": 128
}
```

### Output Fields

- **spi**: Security Parameter Index, a unique identifier for the IPsec SA
- **aeadKeyName**: The AEAD algorithm name (rfc4106(gcm(aes)))
- **aeadKey**: The encryption key displayed as a 72-character hexadecimal string (36 bytes)
- **length**: The ICV (Integrity Check Value) length in bits (128)

### Options

```bash
  -h, --help   help for get
```

### SEE ALSO

* [kmeshctl secret](kmeshctl_secret.md) - Manage IPsec secrets for Kmesh
