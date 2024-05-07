package bpfcache

import (
	"kmesh.net/kmesh/bpf/kmesh/bpf2go"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerField("workload_bpfcache")

type Cache struct {
	bpfMap bpf2go.KmeshCgroupSockWorkloadMaps
}

func NewCache(workloadMap bpf2go.KmeshCgroupSockWorkloadMaps) *Cache {
	return &Cache{
		bpfMap: workloadMap,
	}
}
