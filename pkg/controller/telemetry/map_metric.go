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
	mapName      string
	mapType      string
	entryCount   uint32
	maxEntries   uint32
	memlockBytes uint64
}

type mapMetricLabels struct {
	mapName  string
	nodeName string
}

type detailedMapMetricLabels struct {
	mapName  string
	nodeName string
	mapType  string
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
	return mapMetricLabels{
		nodeName: os.Getenv("NODE_NAME"),
		mapName:  data.mapName,
	}
}

func buildMapMetricDetailedLabel(data *MapInfo) detailedMapMetricLabels {
	return detailedMapMetricLabels{
		mapName:  data.mapName,
		nodeName: os.Getenv("NODE_NAME"),
		mapType:  data.mapType,
	}
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
		if info.Type != ebpf.Hash {
			mapInfo.Close()
			continue
		}
		entryCount, _ := getMapEntryCountFallback(mapInfo)
		mapData := buildMapEntrycountMetric(info, entryCount)
		metricLabels := buildMapMetricLabel(&mapData)
		commonLabels := struct2map(metricLabels)
		mapEntryCount.With(commonLabels).Set(float64(entryCount))

		detailedLabels := buildMapMetricDetailedLabel(&mapData)
		detailedLabelsMap := struct2map(detailedLabels)
		mapMaxEntries.With(detailedLabelsMap).Set(float64(mapData.maxEntries))
		mapMemlockBytes.With(detailedLabelsMap).Set(float64(mapData.memlockBytes))
		if mapData.maxEntries > 0 {
			mapUtilizationRatio.With(detailedLabelsMap).Set(float64(entryCount) / float64(mapData.maxEntries))
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

func buildMapEntrycountMetric(info *ebpf.MapInfo, entryCount uint32) MapInfo {
	memlock, _ := info.Memlock()
	return MapInfo{
		mapName:      info.Name,
		mapType:      info.Type.String(),
		entryCount:   entryCount,
		maxEntries:   info.MaxEntries,
		memlockBytes: memlock,
	}
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
