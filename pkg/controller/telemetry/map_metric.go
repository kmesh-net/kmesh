/*
* Copyright The Kmesh Authors.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at:
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
 */

package telemetry

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
)

const (
	mapMetricFlushInterval = 5 * time.Second
)

type MapMetricController struct {
	mapMetricCache map[mapMetricLabels]*mapUsageInfo
}

type mapUsageMetric struct {
	mapId      uint32
	mapName    string
	mapType    string
	maxEntries uint32
	keySize    uint32
	valueSize  uint32
	memLock    uint32
	entryCount uint32
}

type mapUsageInfo struct {
	memLock    uint32
	entryCount uint32
	maxEntries uint32
}

type mapMetricLabels struct {
	mapId        string
	mapName      string
	mapType      string
	podName      string
	podNamespace string
}

func NewMapMetric() *MapMetricController {
	return &MapMetricController{
		mapMetricCache: map[mapMetricLabels]*mapUsageInfo{},
	}
}

func (m *MapMetricController) Run(ctx context.Context) {
	if m == nil {
		return
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Metrics updated every 5 seconds
				time.Sleep(mapMetricFlushInterval)
				m.updatePrometheusMetric()
			}
		}
	}()
}

func (m *MapMetricController) buildMapMetric(data *mapUsageMetric) mapMetricLabels {
	labels := mapMetricLabels{}
	// Get the actual pod namespace from environment variable "POD_NAMESPACE"
	podNamespace := os.Getenv("POD_NAMESPACE")
	if podNamespace == "" {
		podNamespace = "unknown-pod-namespace"
	}
	podName := os.Getenv("POD_NAME")
	if podName == "" {
		podName = "unknown-pod-name"
	}

	labels.podName = podName
	labels.podNamespace = podNamespace
	labels.mapId = fmt.Sprintf("%d", data.mapId)
	labels.mapName = data.mapName
	labels.mapType = data.mapType
	return labels
}

func (m *MapMetricController) updatePrometheusMetric() {
	var startID ebpf.MapID
	var commonLabels map[string]string
	var entryCount uint32
	count := 0
	currentMapIDs := make(map[string]bool)
	for {
		mapData := mapUsageMetric{}
		// get next map ID
		mapID, err := ebpf.MapGetNextID(startID)
		if err != nil {
			break
		}
		// get map info by map ID
		mapInfo, err := ebpf.NewMapFromID(mapID)
		if err != nil {
			log.Infof("Failed to open map ID %d: %v", mapID, err)
			startID = mapID
			continue
		}
		defer mapInfo.Close()
		info, err := mapInfo.Info()
		if err != nil {
			log.Infof("Failed to get map info for ID %d: %v", mapID, err)
			startID = mapID
			continue
		}
		memLock := (info.KeySize + info.ValueSize) * info.MaxEntries
		if memLock%4096 != 0 {
			memLock = ((memLock / 4096) + 1) * 4096
		}
		if err != nil {
			log.Infof("Failed to get entry count for map ID %d: %v", mapID, err)
		}
		if info.Type != ebpf.RingBuf {
			entryCount, _ = getMapEntryCountFallback(mapInfo)
		} else {
			entryCount = 0
		}
		startID = mapID
		count++
		mapData.mapId = uint32(mapID)
		mapData.mapName = info.Name
		mapData.mapType = type2String(info.Type)
		mapData.maxEntries = info.MaxEntries
		mapData.keySize = info.KeySize
		mapData.valueSize = info.ValueSize
		mapData.memLock = memLock
		mapData.entryCount = entryCount
		metricLabels := m.buildMapMetric(&mapData)
		mapUsageInfo := mapUsageInfo{}
		mapUsageInfo.entryCount = entryCount
		mapUsageInfo.memLock = memLock
		mapUsageInfo.maxEntries = info.MaxEntries
		commonLabels = struct2map(metricLabels)
		currentMapIDs[metricLabels.mapId] = true
		m.mapMetricCache[metricLabels] = &mapUsageInfo
		mapUsage.With(commonLabels).Set(float64(entryCount))
		mapMemory.With(commonLabels).Set(float64(memLock))
		mapMaxEntries.With(commonLabels).Set(float64(info.MaxEntries))
	}
	for labels := range m.mapMetricCache {
		if _, exists := currentMapIDs[labels.mapId]; !exists {
			delete(m.mapMetricCache, labels)
			commonLabels := struct2map(labels)
			mapUsage.Delete(commonLabels)
			mapMemory.Delete(commonLabels)
			mapMaxEntries.Delete(commonLabels)
		}
	}
	mapCountInPod.With(map[string]string{
		"pod_name":      commonLabels["pod_name"],
		"pod_namespace": commonLabels["pod_namespace"],
	}).Set(float64(count))
}
func getMapEntryCountFallback(m *ebpf.Map) (uint32, error) {
	var entryCount uint32
	iterator := m.Iterate()
	var key, value []byte
	for iterator.Next(&key, &value) {
		entryCount++
	}
	if err := iterator.Err(); err != nil {
		return 0, fmt.Errorf("failed during map iteration: %v", err)
	}
	return entryCount, nil
}

func type2String(mt ebpf.MapType) string {
	switch mt {
	case ebpf.Hash:
		return "Hash"
	case ebpf.Array:
		return "Array"
	case ebpf.ProgramArray:
		return "ProgramArray"
	case ebpf.PerfEventArray:
		return "PerfEventArray"
	case ebpf.PerCPUHash:
		return "PerCPUHash"
	case ebpf.PerCPUArray:
		return "PerCPUArray"
	case ebpf.StackTrace:
		return "StackTrace"
	case ebpf.CGroupArray:
		return "CGroupArray"
	case ebpf.LRUHash:
		return "LRUHash"
	case ebpf.LRUCPUHash:
		return "LRUCPUHash"
	case ebpf.LPMTrie:
		return "LPMTrie"
	case ebpf.ArrayOfMaps:
		return "ArrayOfMaps"
	case ebpf.HashOfMaps:
		return "HashOfMaps"
	case ebpf.DevMap:
		return "DevMap"
	case ebpf.SockMap:
		return "SockMap"
	case ebpf.CPUMap:
		return "CPUMap"
	case ebpf.XSKMap:
		return "XSKMap"
	case ebpf.SockHash:
		return "SockHash"
	case ebpf.CGroupStorage:
		return "CGroupStorage"
	case ebpf.ReusePortSockArray:
		return "ReusePortSockArray"
	case ebpf.PerCPUCGroupStorage:
		return "PerCPUCGroupStorage"
	case ebpf.Queue:
		return "Queue"
	case ebpf.Stack:
		return "Stack"
	case ebpf.SkStorage:
		return "SkStorage"
	case ebpf.DevMapHash:
		return "DevMapHash"
	case ebpf.StructOpsMap:
		return "StructOpsMap"
	case ebpf.RingBuf:
		return "RingBuf"
	case ebpf.InodeStorage:
		return "InodeStorage"
	case ebpf.TaskStorage:
		return "TaskStorage"
	default:
		return "Unknown"
	}
}
