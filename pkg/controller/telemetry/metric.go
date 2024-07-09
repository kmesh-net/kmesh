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
	"net"
	"net/netip"
	"reflect"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/bpf"
	bpfCache "kmesh.net/kmesh/pkg/controller/workload/bpfcache"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
)

type Metric struct {
	workloadCache cache.WorkloadCache
	bpf           *bpfCache.Cache
}

func NewMetric(workloadCache cache.WorkloadCache, bpfWorkload *bpf.BpfKmeshWorkload) *Metric {
	return &Metric{
		workloadCache: workloadCache,
		bpf:           bpfCache.NewCache(bpfWorkload.SockConn.KmeshCgroupSockWorkloadMaps),
	}
}

func (m *Metric) Run(ctx context.Context, mapOfMetricNotify, mapOfMetric *ebpf.Map) {
	if m == nil {
		return
	}

	reader, err := ringbuf.NewReader(mapOfMetricNotify)
	if err != nil {
		log.Errorf("open metric notify ringbuf map FAILED, err: %v", err)
		return
	}
	defer func() {
		if err := reader.Close(); err != nil {
			log.Errorf("ringbuf reader Close FAILED, err: %v", err)
		}
	}()

	// Register metrics to Prometheus and start Prometheus server
	go RunPrometheusClient()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			rec := ringbuf.Record{}
			key := metricKey{}
			value := metricValue{}
			data := requestMetric{}
			if err := reader.ReadInto(&rec); err != nil {
				log.Errorf("ringbuf reader FAILED to read, err: %v", err)
				continue
			}

			buf := bytes.NewBuffer(rec.RawSample)
			if err := binary.Read(buf, binary.LittleEndian, &key); err != nil {
				log.Error("deserialize request link info FAILED, err:", err)
				continue
			}

			if err := mapOfMetric.Lookup(&key, &value); err != nil {
				log.Error("get bpf map of metrics FAILED, err:", err)
				continue
			}
			// The data in the Key is in IPv6 format
			for i := range key.SrcIp {
				data.src = binary.BigEndian.AppendUint32(data.src, key.SrcIp[i])
				data.dst = binary.BigEndian.AppendUint32(data.dst, key.DstIp[i])
			}
			data.connectionClosed = value.ConnectionClose
			data.connectionOpened = value.ConnectionOpen
			data.sentBytes = value.SentBytes
			data.receivedBytes = value.ReceivedBytes
			data.success = true

			commonTrafficLabels, err := m.buildMetric(&data)
			if err != nil {
				log.Warnf("reporter records error")
			}

			reporter := fmt.Sprintf("%d", value.Direction)
			if reporter == "1" {
				commonTrafficLabels.direction = "INBOUND"
			} else if reporter == "2" {
				commonTrafficLabels.direction = "OUTBOUND"
			} else {
				commonTrafficLabels.direction = "-"
			}

			buildMetricsToPrometheus(data, commonTrafficLabels)
		}
	}
}

func (m *Metric) buildMetric(data *requestMetric) (commonTrafficLabels, error) {
	var dstAddr, srcAddr []byte
	dstAddr = ByteToIpByte(data.dst)
	srcAddr = ByteToIpByte(data.src)
	dstWorkload := m.getWorkloadByAddress(dstAddr)
	srcWorkload := m.getWorkloadByAddress(srcAddr)

	trafficLabels := buildMetricFromWorkload(dstWorkload, srcWorkload)
	trafficLabels.destinationService = ConvertUint32ToIp(ConvertIpByteToUint32(dstAddr))

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
	connectionOpened = binary.BigEndian.AppendUint32(connectionOpened, data.connectionOpened)
	connectionClosed = binary.BigEndian.AppendUint32(connectionClosed, data.connectionClosed)
	receivedBytes = binary.BigEndian.AppendUint32(receivedBytes, data.receivedBytes)
	sentBytes = binary.BigEndian.AppendUint32(sentBytes, data.sentBytes)

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

// ConvertUint32ToIp converts big-endian uint32 to ip format
func ConvertUint32ToIp(big uint32) string {
	netIP := make(net.IP, 4)
	binary.LittleEndian.PutUint32(netIP, big)
	return netIP.String()
}

func ConvertIpByteToUint32(ip []byte) uint32 {
	if len(ip) != 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(ip)
}

// Converting IPv4 data reported in IPv6 form to IPv4
func ByteToIpByte(bytes []byte) []byte {
	l := len(bytes)
	result := make([]byte, l)

	for i := 0; i < l; i++ {
		result[i] = bytes[l-i-1]
	}

	for i := 0; i < 12; i++ {
		if result[i] != byte(0) {
			return result
		}
	}

	return result[12:]
}
