---
title: kmeshctl secret
sidebar_position: 6
---

### Use IPsec in Kmesh cluster

IPsec is a mature and widely used encryption method for inter-node communication. This document explains how to enable IPsec to encrypt communication data between Kmesh-managed nodes.

### kmeshctl secret command Examples

The `kmeshctl secret` command provides management capabilities for IPsec secrets in Kmesh clusters. It supports the following subcommands:

- `create`: Generate and store IPsec key and configuration
- `get`: Retrieve current IPsec key and configuration (displayed in JSON format)
- `delete`: Remove IPsec secret from the cluster

#### Basic usage examples

```bash
# Create IPsec secret with random key
kmeshctl secret create

# Create IPsec secret with custom key
kmeshctl secret create --key=$(echo -n "{36-character user-defined key here}" | xxd -p -c 64)

# Get current IPsec configuration
kmeshctl secret get

# Delete IPsec secret
kmeshctl secret delete
```

### How to enable IPsec in Kmesh

#### Step 1: Generate an IPsec pre-shared key for Kmesh before starting Kmesh. Currently, only the rfc4106 (gcm(AES)) algorithm is supported. The key must be 36 bytes (32 bytes for the algorithm key and 4 bytes for the salt), provided as a 72-character hexadecimal string

If you want to use a randomly generated key, you can use the following command:

``` bash
kmeshctl secret create
```

If you want to use a custom key, you can use the following command:

``` bash
kmeshctl secret create --key=$(echo -n "{36-character user-defined key here}" | xxd -p -c 64)
```

#### Step 2: Add the parameter --enable-ipsec=true to the Kmesh yaml

```plaintext
kmesh.yaml
...
args:
[
    "./start_kmesh.sh --mode=ads-v2 --enable-bypass=false --enable-ipsec=true",
]
...
```

#### Step 3: Place pods or namespace under the management of Kmesh

Only when both communicating pods are managed by Kmesh, will they enter the encryption process.

``` bash
kubectl label namespace default istio.io/dataplane-mode=Kmesh
```

#### Step 4: Test whether the data packet has been encrypted

Use tcpdump on nodes to capture packets and check if IPsec has been used during data communication between nodes (determined by ESP packets)

```plaintext
tcpdump -i any |grep ESP
...
14:19:24.143654 ?    Out IP master > node1: ESP(spi=0x00000001,seq=0x3da88), length 80
14:19:24.143690 ?    Out IP master > node1: ESP(spi=0x00000001,seq=0x3da89), length 80
14:19:24.143707 ?    In  IP node1 > master: ESP(spi=0x00000001,seq=0x3c037), length 80
14:19:24.143738 ?    In  IP node1 > master: ESP(spi=0x00000001,seq=0x3c038), length 172
...
```

#### Step 5: Replace pre-shared key

After a period of time, the pre-shared key of the cluster can be changed. After changing the pre-shared key, the ESP SPI number of the IPsec used for communication between nodes will be increased by 1 compared to the previous version. This can be observed again through using tcpdump. The initial IPsec SPI version number is 1.

To replace the existing pre-shared key, run the `kmeshctl secret create` command again.

```plaintext
root@master:~/kmesh# tcpdump -i any |grep ESP
...
14:26:33.782665 ?    Out IP master > node1: ESP(spi=0x00000002,seq=0x1aaa1), length 80
14:26:33.782666 ?    Out IP master > node1: ESP(spi=0x00000002,seq=0x1aaa2), length 80
14:26:33.782667 ?    In  IP node1 > master: ESP(spi=0x00000002,seq=0x183d2), length 80
14:26:33.782667 ?    In  IP node1 > master: ESP(spi=0x00000002,seq=0x183d3), length 80
...
```

### Note

1. IPsec encryption uses mark `0xe0` and `0xd0` as markers for IPsec encryption and decryption. Please ensure that no conflicting Mark is used on the host network, otherwise unknown behavior may occur

2. Please ensure that `address MASQ` is not used on packets encrypted with IPsec. After address MASQ, IPsec cannot accurately match encryption and decryption rules, which can result in packet loss
