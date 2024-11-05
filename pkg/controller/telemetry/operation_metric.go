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
	"encoding/binary"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	OPERATION_USAGE_DATA_LEN = 32

	operationMetricFlushInterval = 5 * time.Second
)
const (
	SOCK_TRAFFIC_CONTROL     = 1
	XDP_SHUTDOWN             = 2
	ENABLE_ENCODING_METADATA = 3
)

var operationTypeMap = map[uint32]string{
	SOCK_TRAFFIC_CONTROL:     "SOCK_TRAFFIC_CONTROL",
	XDP_SHUTDOWN:             "XDP_SHUTDOWN",
	ENABLE_ENCODING_METADATA: "ENABLE_ENCODING_METADATA",
}

type OperationMetricController struct {
	operationMetricCache map[operationMetricLabels]*operationUsageInfo
	mutex                sync.RWMutex
}

type operationUsageMetric struct {
	startTime     uint64
	endTime       uint64
	pidTgid       uint64
	operationType uint32
}

type operationUsageInfo struct {
	durations     []uint64
	operationType uint32
}

type operationMetricLabels struct {
	nodeName      string
	operationType string
}

func NewOperationMetric() *OperationMetricController {
	return &OperationMetricController{
		operationMetricCache: map[operationMetricLabels]*operationUsageInfo{},
	}
}

func (m *OperationMetricController) Run(ctx context.Context, KmeshPerfInfo *ebpf.Map) {
	if m == nil {
		return
	}
	var err error
	readerPerformance, err := ringbuf.NewReader(KmeshPerfInfo)
	if err != nil {
		log.Errorf("open performance notify ringbuf map FAILED, err: %v", err)
		return
	}
	defer func() {
		if err := readerPerformance.Close(); err != nil {
			log.Errorf("ringbuf reader Close FAILED, err: %v", err)
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(operationMetricFlushInterval)
				m.updatePrometheusMetric()
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			operationData := operationUsageMetric{}
			rec := ringbuf.Record{}
			if err := readerPerformance.ReadInto(&rec); err != nil {
				log.Errorf("ringbuf reader FAILED to read, err: %v", err)
				continue
			}
			if len(rec.RawSample) != OPERATION_USAGE_DATA_LEN {
				log.Errorf("wrong length %v of a msg, should be %v", len(rec.RawSample), OPERATION_USAGE_DATA_LEN)
				continue
			}
			operationData.startTime = binary.LittleEndian.Uint64(rec.RawSample[0:8])
			operationData.endTime = binary.LittleEndian.Uint64(rec.RawSample[8:16])
			operationData.pidTgid = binary.LittleEndian.Uint64(rec.RawSample[16:24])
			operationData.operationType = binary.LittleEndian.Uint32(rec.RawSample[24:28])
			metricLabels := m.buildOperationMetric(&operationData)
			operationInfo := operationUsageInfo{
				durations:     []uint64{operationData.endTime - operationData.startTime},
				operationType: operationData.operationType,
			}
			m.mutex.Lock()
			m.updateOperationMetricCache(operationInfo, metricLabels)
			m.mutex.Unlock()
		}
	}
}

// buildOperationMetric builds the operation metrics labels using actual pod info.
func (m *OperationMetricController) buildOperationMetric(data *operationUsageMetric) operationMetricLabels {
	labels := operationMetricLabels{}
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		nodeName = "unknown"
	}
	labels.nodeName = nodeName
	labels.operationType = operationTypeMap[data.operationType]
	return labels
}

func (m *OperationMetricController) updateOperationMetricCache(data operationUsageInfo, labels operationMetricLabels) {
	v, ok := m.operationMetricCache[labels]
	if ok {
		v.durations = append(v.durations, data.durations...)
	} else {
		m.operationMetricCache[labels] = &data
	}
}

func (m *OperationMetricController) updatePrometheusMetric() {
	m.mutex.Lock()
	operationInfoCache := m.operationMetricCache
	m.operationMetricCache = map[operationMetricLabels]*operationUsageInfo{}
	m.mutex.Unlock()
	for k, v := range operationInfoCache {
		commonLabels := struct2map(k)
		for _, duration := range v.durations {
			operationDurationInPod.With(commonLabels).Observe(float64(duration))
			operationCountInPod.With(commonLabels).Inc()
		}
	}
}
