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
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

const (
	mapMetricFlushInterval = 15 * time.Second
)

type MapMetricController struct {
}

type MapInfo struct {
	mapName     string
	mapType     string
	entryCount  uint32
	hasEntry    bool
	maxEntries  uint32
	memlockByte uint64
	hasMemlock  bool
}

type mapMetricLabels struct {
	mapName  string
	nodeName string
}

type mapDetailMetricLabels struct {
	mapName  string
	mapType  string
	nodeName string
}

func NewMapMetric() *MapMetricController {
	return &MapMetricController{}
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
				time.Sleep(mapMetricFlushInterval)
				m.updatePrometheusMetric()
			}
		}
	}()
}

func buildMapMetricLabel(data *MapInfo) mapMetricLabels {
	labels := mapMetricLabels{
		nodeName: os.Getenv("NODE_NAME"),
		mapName:  data.mapName,
	}
	return labels
}

func buildMapDetailMetricLabel(data *MapInfo) mapDetailMetricLabels {
	labels := mapDetailMetricLabels{
		nodeName: os.Getenv("NODE_NAME"),
		mapName:  data.mapName,
		mapType:  data.mapType,
	}
	return labels
}

func isKmeshMap(mapName string) bool {
	return strings.HasPrefix(mapName, "kmesh_")
}
func (m *MapMetricController) updatePrometheusMetric() {
	var startID ebpf.MapID
	count := 0

	// TODO: should we use the maps already known from CollectionSpec

	for {
		mapID, mapInfo, info, err := getNextMapInfo(startID)
		if err != nil {
			break
		}
		startID = mapID
		if info.Name == "" {
			mapInfo.Close()
			count++
			continue
		}

		if !isKmeshMap(info.Name) {
			mapInfo.Close()
			continue
		}
		count++
		entryCount := uint32(0)
		hasEntry := false
		if info.Type == ebpf.Hash {
			hasEntry = true
			entryCount, _ = getMapEntryCountFallback(mapInfo)
		}

		memlockBytes, hasMemlock := info.Memlock()
		mapData := buildMapMetricData(info, entryCount, hasEntry, memlockBytes, hasMemlock)
		metricLabels := buildMapMetricLabel(&mapData)
		commonLabels := struct2map(metricLabels)
		if mapData.hasEntry {
			mapEntryCount.With(commonLabels).Set(float64(mapData.entryCount))
		}

		detailMetricLabels := buildMapDetailMetricLabel(&mapData)
		detailCommonLabels := struct2map(detailMetricLabels)
		mapMaxEntries.With(detailCommonLabels).Set(float64(mapData.maxEntries))
		if mapData.hasEntry {
			mapEntryUtilizationRatio.With(detailCommonLabels).Set(calculateMapEntryUtilization(mapData.entryCount, mapData.maxEntries))
		}
		if mapData.hasMemlock {
			mapMemlockBytes.With(detailCommonLabels).Set(float64(mapData.memlockByte))
		}
		mapInfo.Close()
	}
	mapCountLabels := map[string]string{"node_name": os.Getenv("NODE_NAME")}
	mapCountInNode.With(mapCountLabels).Set(float64(count))
}

func getNextMapInfo(startID ebpf.MapID) (ebpf.MapID, *ebpf.Map, *ebpf.MapInfo, error) {
	mapID, err := ebpf.MapGetNextID(startID)
	if err != nil {
		return 0, nil, nil, err
	}

	mapInfo, err := ebpf.NewMapFromID(mapID)
	if err != nil {
		log.Infof("Failed to open map ID %d: %v", mapID, err)
		return mapID, nil, nil, err
	}

	info, err := mapInfo.Info()
	if err != nil {
		log.Infof("Failed to get map info for ID %d: %v", mapID, err)
		return mapID, mapInfo, nil, err
	}

	return mapID, mapInfo, info, nil
}

func buildMapMetricData(info *ebpf.MapInfo, entryCount uint32, hasEntry bool, memlockBytes uint64, hasMemlock bool) MapInfo {
	return MapInfo{
		mapName:     info.Name,
		mapType:     info.Type.String(),
		entryCount:  entryCount,
		hasEntry:    hasEntry,
		maxEntries:  info.MaxEntries,
		memlockByte: memlockBytes,
		hasMemlock:  hasMemlock,
	}
}

func calculateMapEntryUtilization(entryCount, maxEntries uint32) float64 {
	if maxEntries == 0 {
		return 0
	}
	return float64(entryCount) / float64(maxEntries)
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
