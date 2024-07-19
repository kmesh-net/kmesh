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
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"reflect"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
)

type MetricController struct {
	workloadCache cache.WorkloadCache
}

type metricKey struct {
	SrcIp [4]uint32
	DstIp [4]uint32
}

type metricValue struct {
	Direction        uint32
	ConnectionOpen   uint32
	ConnectionClose  uint32
	ConnectionFailed uint32
	SentBytes        uint32
	ReceivedBytes    uint32
}

type requestMetric struct {
	src              [4]uint32
	dst              [4]uint32
	connectionOpened uint32
	connectionClosed uint32
	receivedBytes    uint32
	sentBytes        uint32
	success          bool
}

type commonTrafficLabels struct {
	reporter string

	sourceWorkload          string
	sourceCanonicalService  string
	sourceCanonicalRevision string
	sourceWorkloadNamespace string
	sourcePrincipal         string
	sourceApp               string
	sourceVersion           string
	sourceCluster           string

	destinationService           string
	destinationServiceNamespace  string
	destinationServiceName       string
	destinationWorkload          string
	destinationCanonicalService  string
	destinationCanonicalRevision string
	destinationWorkloadNamespace string
	destinationPrincipal         string
	destinationApp               string
	destinationVersion           string
	destinationCluster           string

	requestProtocol          string
	responseFlags            string
	connectionSecurityPolicy string
}

func NewMetric(workloadCache cache.WorkloadCache) *MetricController {
	return &MetricController{
		workloadCache: workloadCache,
	}
}

func (m *MetricController) Run(ctx context.Context, mapOfMetricNotify, mapOfMetric *ebpf.Map) {
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
	go RunPrometheusClient(ctx)

	rec := ringbuf.Record{}
	key := metricKey{}
	value := metricValue{}
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
			if err := binary.Read(buf, binary.LittleEndian, &key); err != nil {
				log.Error("get metric key FAILED, err:", err)
				continue
			}

			if err := mapOfMetric.Lookup(&key, &value); err != nil {
				log.Error("get bpf map of metric FAILED, err:", err)
				continue
			}

			data.src = key.SrcIp
			data.dst = key.DstIp
			data.connectionClosed = value.ConnectionClose
			data.connectionOpened = value.ConnectionOpen
			data.sentBytes = value.SentBytes
			data.receivedBytes = value.ReceivedBytes
			data.success = true

			commonTrafficLabels, err := m.buildMetric(&data)
			if err != nil {
				log.Warnf("reporter records error")
			}

			commonTrafficLabels.reporter = "-"
			if value.Direction == constants.INBOUND {
				commonTrafficLabels.reporter = "destination"
			}
			if value.Direction == constants.OUTBOUND {
				commonTrafficLabels.reporter = "source"
			}

			buildMetricsToPrometheus(data, commonTrafficLabels)
		}
	}
}

func (m *MetricController) buildMetric(data *requestMetric) (commonTrafficLabels, error) {
	var dstAddr, srcAddr []byte
	for i := range data.dst {
		dstAddr = binary.LittleEndian.AppendUint32(dstAddr, data.dst[i])
		srcAddr = binary.LittleEndian.AppendUint32(srcAddr, data.src[i])
	}

	dstWorkload, _ := m.getWorkloadByAddress(restoreIPv4(dstAddr))
	srcWorkload, _ := m.getWorkloadByAddress(restoreIPv4(srcAddr))

	trafficLabels := buildMetricFromWorkload(dstWorkload, srcWorkload)

	trafficLabels.requestProtocol = "tcp"
	trafficLabels.responseFlags = "-"
	trafficLabels.connectionSecurityPolicy = "mutual_tls"

	return trafficLabels, nil
}

func (m *MetricController) getWorkloadByAddress(address []byte) (*workloadapi.Workload, string) {
	networkAddr := cache.NetworkAddress{}
	networkAddr.Address, _ = netip.AddrFromSlice(address)
	workload := m.workloadCache.GetWorkloadByAddr(networkAddr)
	if workload == nil {
		log.Warnf("get workload from ip %v FAILED", address)
		return nil, ""
	}
	return workload, networkAddr.Address.String()
}

func buildMetricFromWorkload(dstWorkload, srcWorkload *workloadapi.Workload) commonTrafficLabels {
	if dstWorkload == nil || srcWorkload == nil {
		return commonTrafficLabels{}
	}

	trafficLabels := commonTrafficLabels{}
	services := dstWorkload.Services
	svcHost := ""
	for k, _ := range services {
		svcHost = strings.Split(k, "/")[1]
	}
	svcName := strings.Split(svcHost, ".")[0]

	trafficLabels.destinationServiceNamespace = dstWorkload.Namespace
	trafficLabels.destinationServiceName = svcName
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

	trafficLabels.destinationService = svcHost

	return trafficLabels
}

func buildPrincipal(workload *workloadapi.Workload) string {
	if workload.TrustDomain != "" && workload.ServiceAccount != "" && workload.Namespace != "" {
		return fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", workload.TrustDomain, workload.Namespace, workload.ServiceAccount)
	}
	return "-"
}

func buildMetricsToPrometheus(data requestMetric, labels commonTrafficLabels) {
	commonLabels := commonTrafficLabels2map(&labels)
	tcpConnectionOpened.With(commonLabels).Set(float64(data.connectionOpened))
	tcpConnectionClosed.With(commonLabels).Set(float64(data.connectionClosed))
	tcpReceivedBytes.With(commonLabels).Set(float64(data.receivedBytes))
	tcpSentBytes.With(commonLabels).Set(float64(data.sentBytes))
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

// Converting IPv4 data reported in IPv6 form to IPv4
func restoreIPv4(bytes []byte) []byte {
	for i := 4; i < 16; i++ {
		if bytes[i] != 0 {
			return bytes
		}
	}

	return bytes[:4]
}
