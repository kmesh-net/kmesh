//go:build !linux
// +build !linux

package unix

// various constants
const (
	NETLINK_NETFILTER = 0xc
	NFNETLINK_V0      = 0x0
	AF_UNSPEC         = 0x0
	AF_INET           = 0x2
	AF_INET6          = 0xa
	AF_BRIDGE         = 0x7
)
