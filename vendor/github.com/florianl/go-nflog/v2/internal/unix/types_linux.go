//go:build linux
// +build linux

package unix

import linux "golang.org/x/sys/unix"

// various constants
const (
	NETLINK_NETFILTER = linux.NETLINK_NETFILTER
	NFNETLINK_V0      = linux.NFNETLINK_V0
	AF_UNSPEC         = linux.AF_UNSPEC
	AF_INET           = linux.AF_INET
	AF_INET6          = linux.AF_INET6
	AF_BRIDGE         = linux.AF_BRIDGE
)
