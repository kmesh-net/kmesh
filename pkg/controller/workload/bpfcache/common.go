package bpfcache

import (
	"github.com/cilium/ebpf"
)

func LookupAll[T any](bpfMap *ebpf.Map) []T {
	var (
		key   T
		value T
		ret   []T
	)

	iter := bpfMap.Iterate()
	for iter.Next(&key, &value) {
		ret = append(ret, value)
	}
	return ret
}
