/*
 * Copyright 2024 The Kmesh Authors.
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
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"reflect"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"istio.io/istio/pkg/slices"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
	"kmesh.net/kmesh/pkg/nets"
)

type Metric struct {
	workloadCache cache.WorkloadCache
}

func NewMetric(workloadCache cache.WorkloadCache) *Metric {
	return &Metric{
		workloadCache: workloadCache,
	}
}

func (m *Metric) Run(ctx context.Context, mapOfTuple *ebpf.Map) {
	if m == nil {
		return
	}

	reader, err := ringbuf.NewReader(mapOfTuple)
	if err != nil {
		log.Errorf("open ringbuf map FAILED, err: %v", err)
		return
	}
	defer func() {
		if err := reader.Close(); err != nil {
			log.Errorf("reader Close FAILED, err: %v", err)
		}
	}()

	// Register metrics to Prometheus
	go RunPrometheusClient()

	// TODO: Turn ringbuf fetch metrics into bpf map fetch
	rec := ringbuf.Record{}
	data := requestMetric{}
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if err := reader.ReadInto(&rec); err != nil {
				log.Errorf("ringbuf reader FAILED to read, err: %v", err)
				continue
			}

			buf := bytes.NewBuffer(rec.RawSample)
			if err = binary.Read(buf, binary.LittleEndian, &data); err != nil {
				log.Errorf("deserialize request trafficLabels FAILED, err: %v", err)
				continue
			}

			commonTrafficLabels, err := m.buildMetric(&data)
			if err != nil {
				log.Warnf("reporter records error")
			}

			buildMetricsToPrometheus(data, commonTrafficLabels)
		}
	}
}

func (m *Metric) buildMetric(data *requestMetric) (commonTrafficLabels, error) {
	dstAddr := data.dst
	srcAddr := data.src
	dstWorkload := m.getWorkloadByAddress(dstAddr)
	fmt.Printf("%#v\n", dstWorkload)
	srcWorkload := m.getWorkloadByAddress(srcAddr)
	fmt.Printf("%#v\n", srcWorkload)

	trafficLabels := buildMetricFromWorkload(dstWorkload, srcWorkload)
	fmt.Printf("%#v", trafficLabels)
	trafficLabels.destinationService = nets.ConvertUint32ToIp(nets.ConvertIpByteToUint32(dstAddr))

	reporter := data.reporter
	if slices.Equal(reporter, dstAddr) {
		trafficLabels.reporter = "destination"
	} else if slices.Equal(reporter, srcAddr) {
		trafficLabels.reporter = "source"
	} else {
		return commonTrafficLabels{}, fmt.Errorf("reporter records error")
	}

	trafficLabels.requestProtocol = "tcp"
	trafficLabels.responseFlags = "-"
	trafficLabels.connectionSecurityPolicy = "mutual_tls"

	return trafficLabels, nil
}

func (m *Metric) getWorkloadByAddress(address []byte) *workloadapi.Workload {
	networkAddr := cache.NetworkAddress{}
	networkAddr.Address, _ = netip.AddrFromSlice(address)
	workload := m.workloadCache.GetWorkloadByAddr(networkAddr)
	if workload == nil {
		log.Warnf("get worload from ip %v FAILED", address)
		return nil
	}
	return workload
}

func buildMetricFromWorkload(dstWorkload, srcWorkload *workloadapi.Workload) commonTrafficLabels {
	if dstWorkload == nil || srcWorkload == nil {
		return commonTrafficLabels{}
	}

	trafficLabels := commonTrafficLabels{}

	trafficLabels.destinationServiceNamespace = dstWorkload.Namespace
	trafficLabels.destinationServiceName = dstWorkload.Name
	trafficLabels.destinationWorkload = dstWorkload.WorkloadName
	trafficLabels.destinationCanonicalService = dstWorkload.CanonicalName
	trafficLabels.destinationCanonicalRevision = dstWorkload.CanonicalRevision
	trafficLabels.destinationWorkloadNamespace = dstWorkload.Namespace
	trafficLabels.destinationApp = dstWorkload.CanonicalName
	trafficLabels.destinationVersion = dstWorkload.CanonicalRevision
	trafficLabels.destinationCluster = dstWorkload.ClusterId

	trafficLabels.sourceWorkload = srcWorkload.WorkloadName
	trafficLabels.sourceCanonicalService = srcWorkload.CanonicalName
	trafficLabels.sourceCanonicalRevision = srcWorkload.CanonicalRevision
	trafficLabels.sourceWorkloadNamespace = srcWorkload.Namespace
	trafficLabels.sourceApp = srcWorkload.CanonicalName
	trafficLabels.sourceVersion = srcWorkload.CanonicalRevision
	trafficLabels.sourceCluster = srcWorkload.ClusterId

	trafficLabels.destinationPrincipal = buildPrincipal(dstWorkload)
	trafficLabels.sourcePrincipal = buildPrincipal(srcWorkload)

	return trafficLabels
}

func buildPrincipal(workload *workloadapi.Workload) string {
	if workload.TrustDomain != "" && workload.ServiceAccount != "" && workload.Namespace != "" {
		return fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", workload.TrustDomain, workload.Namespace, workload.ServiceAccount)
	}
	return "-"
}

func buildMetricsToPrometheus(data requestMetric, labels commonTrafficLabels) {
	connectionOpened, connectionClosed, receivedBytes, sentBytes := []byte{}, []byte{}, []byte{}, []byte{}
	connectionOpened = binary.LittleEndian.AppendUint32(connectionOpened, data.connectionOpened)
	connectionClosed = binary.LittleEndian.AppendUint32(connectionClosed, data.connectionClosed)
	receivedBytes = binary.LittleEndian.AppendUint32(receivedBytes, data.receivedBytes)
	sentBytes = binary.LittleEndian.AppendUint32(sentBytes, data.sentBytes)

	commonLabels := commonTrafficLabels2map(&labels)
	tcpConnectionOpened.With(commonLabels).Set(byteToFloat64(connectionOpened))
	tcpConnectionClosed.With(commonLabels).Set(byteToFloat64(connectionClosed))
	tcpReceivedBytes.With(commonLabels).Set(byteToFloat64(receivedBytes))
	tcpSentBytes.With(commonLabels).Set(byteToFloat64(sentBytes))
}

func commonTrafficLabels2map(labels *commonTrafficLabels) map[string]string {
	trafficLabelsMap := make(map[string]string)

	val := reflect.ValueOf(labels).Elem()
	num := val.NumField()
	for i := 0; i < num; i++ {
		fieldInfo := val.Type().Field(i)
		if val.Field(i).String() == "" {
			trafficLabelsMap[labelsMap[fieldInfo.Name]] = "-"
		} else {
			trafficLabelsMap[labelsMap[fieldInfo.Name]] = val.Field(i).String()
		}
	}

	return trafficLabelsMap
}

func byteToFloat64(bytesData []byte) float64 {
	var i int64
	if len(bytesData) != 8 {
		u32 := binary.LittleEndian.Uint32(bytesData)
		u64 := uint64(u32)
		i = int64(u64)
	} else {
		u64 := binary.LittleEndian.Uint64(bytesData)
		i = int64(u64)
	}
	return float64(i)
}
