go-nflog [![PkgGoDev](https://pkg.go.dev/badge/github.com/florianl/go-nflog)](https://pkg.go.dev/github.com/florianl/go-nflog) [![Go Report Card](https://goreportcard.com/badge/github.com/florianl/go-nflog)](https://goreportcard.com/report/github.com/florianl/go-nflog) [![Go](https://github.com/florianl/go-nflog/actions/workflows/go.yml/badge.svg)](https://github.com/florianl/go-nflog/actions/workflows/go.yml)
============

This is `go-nflog` and it is written in [golang](https://golang.org/). It provides a [C](https://en.wikipedia.org/wiki/C_(programming_language))-binding free API to the netfilter based log subsystem of the [Linux kernel](https://www.kernel.org).

## Example

```golang
func main() {
	// Send outgoing pings to nflog group 100
	// # sudo iptables -I OUTPUT -p icmp -j NFLOG --nflog-group 100

	//Set configuration parameters
	config := nflog.Config{
		Group:       100,
		Copymode:    nflog.CopyPacket,
	}

	nf, err := nflog.Open(&config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not open nflog socket:", err)
		return
	}
	defer nf.Close()

	// Avoid receiving ENOBUFS errors.
	if err := nf.SetOption(netlink.NoENOBUFS, true); err != nil {
		fmt.Fprintf(os.Stderr, "failed to set netlink option %v: %v",
			netlink.NoENOBUFS, err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// hook that is called for every received packet by the nflog group
	hook := func(attrs nflog.Attribute) int {
		// Just print out the payload of the nflog packet
		fmt.Fprintf(os.Stdout, "%#v\n", attrs.Payload)
		return 0
	}

	// errFunc that is called for every error on the registered hook
	errFunc := func(e error) int {
		// Just log the error and return 0 to continue receiving packets
		fmt.Fprintf(os.Stderr, "received error on hook: %v", e)
		return 0
	}

	// Register your function to listen on nflog group 100
	err = nf.RegisterWithErrorFunc(ctx, hook, errFunc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to register hook function: %v", err)
		return
	}

	// Block till the context expires
	<-ctx.Done()
}
```

## Privileges

This package processes information directly from the kernel and therefore it requires special privileges. You
can provide this privileges by adjusting the `CAP_NET_ADMIN` capabilities.
```
	setcap 'cap_net_admin=+ep' /your/executable
```

For documentation and more examples please take a look at [![PkgGoDev](https://pkg.go.dev/badge/github.com/florianl/go-nflog)](https://pkg.go.dev/github.com/florianl/go-nflog)

## Requirements

* A version of Go that is [supported by upstream](https://golang.org/doc/devel/release.html#policy)
