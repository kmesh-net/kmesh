package bpfcache

import "kmesh.net/kmesh/pkg/logger"

var log = logger.NewLoggerField("workload_cache")

type Cache struct {
	bpfMap bpf2go.KmeshCgroupSockWorkloadMaps
}

func NewCache(workloadMap bpf2go.KmeshCgroupSockWorkloadMaps) *Cache {
	return &Cache{
		bpfMap: workloadMap,
	}
}
