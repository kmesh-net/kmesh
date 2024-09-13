package bpfcache

import (
	"github.com/cilium/ebpf"
)

func LookupAll[K any, V any](bpfMap *ebpf.Map) []V {
	var (
		key   K
		value V
		ret   []V
	)

	iter := bpfMap.Iterate()
	for iter.Next(&key, &value) {
		ret = append(ret, value)
	}
	return ret
}
