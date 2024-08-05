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
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
)

const (
	MSG_TYPE_IPV4 = uint32(2)
	MSG_TYPE_IPV6 = uint32(10)
)

type MetricController struct {
	workloadCache cache.WorkloadCache
}

// type metricKey struct {
// 	SrcIp     [4]uint32
// 	DstIp     [4]uint32
// 	Direction uint32
// 	DstPort   uint32
// }

// type metricValue struct {
// 	ConnectionOpen   uint32
// 	ConnectionClose  uint32
// 	ConnectionFailed uint32
// 	SentBytes        uint32
// 	ReceivedBytes    uint32
// }

type connectionDataV4 struct {
	SrcAddr        uint32
	DstAddr        uint32
	SrcPort        uint16
	DstPort        uint16
	RedundantData  [6]uint32
	SentBytes      uint32
	ReceivedBytes  uint32
	ConnectSuccess uint32
	Direction      uint32
	State          uint32
}

type connectionDataV6 struct {
	SrcAddr        [4]uint32
	DstAddr        [4]uint32
	SrcPort        uint16
	DstPort        uint16
	SentBytes      uint32
	ReceivedBytes  uint32
	ConnectSuccess uint32
	Direction      uint32
	State          uint32
}

type requestMetric struct {
	src           [4]uint32
	dst           [4]uint32
	dstPort       uint16
	direction     uint32
	receivedBytes uint32
	sentBytes     uint32
	state         uint32
	success       uint32
}

type workloadMetricLabels struct {
	reporter string

	sourceWorkload          string
	sourceCanonicalService  string
	sourceCanonicalRevision string
	sourceWorkloadNamespace string
	sourcePrincipal         string
	sourceApp               string
	sourceVersion           string
	sourceCluster           string

	destinationPodAddress        string
	destinationPodNamespace      string
	destinationPodName           string
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

type serviceMetricLabels struct {
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

func (m *MetricController) Run(ctx context.Context, mapOfTcpInfo *ebpf.Map) {
	if m == nil {
		return
	}

	reader, err := ringbuf.NewReader(mapOfTcpInfo)
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
	// key := metricKey{}
	// value := metricValue{}
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

			connectType := binary.LittleEndian.Uint32(rec.RawSample)
			originInfo := rec.RawSample[unsafe.Sizeof(connectType):]
			fmt.Printf("\n***************** %#v ************\n", originInfo)
			buf := bytes.NewBuffer(originInfo)
			switch connectType {
			case MSG_TYPE_IPV4:
				data, err = connV4BuildData(buf)
			case MSG_TYPE_IPV6:
				data, err = connV6BuildData(buf)
			default:
				log.Errorf("get connection info failed: %v", err)
				continue
			}

			fmt.Printf("\n-----------request data is : %#v ---------\n", data)

			if data.state != uint32(7) {
				continue
			}

			workloadLabels := m.buildWorkloadMetric(&data)
			serviceLabels := m.buildServiceMetric(&data)

			workloadLabels.reporter = "-"
			serviceLabels.reporter = "-"
			if data.direction == constants.INBOUND {
				workloadLabels.reporter = "destination"
				serviceLabels.reporter = "destination"
			}
			if data.direction == constants.OUTBOUND {
				workloadLabels.reporter = "source"
				serviceLabels.reporter = "source"
			}

			buildWorkloadMetricsToPrometheus(data, workloadLabels)
			buildServiceMetricsToPrometheus(data, serviceLabels)
		}
	}
}

func connV4BuildData(buf *bytes.Buffer) (requestMetric, error) {
	data := requestMetric{}
	connectData := connectionDataV4{}
	if err := binary.Read(buf, binary.LittleEndian, &connectData); err != nil {
		return data, err
	}

	fmt.Printf("\n----------- v4 info is: %#v ---------\n", connectData)
	data.src[0] = connectData.SrcAddr
	data.dst[0] = connectData.DstAddr
	data.direction = connectData.Direction
	data.dstPort = connectData.DstPort
	// data.connectionClosed = value.ConnectionClose
	// data.connectionOpened = value.ConnectionOpen
	data.sentBytes = connectData.SentBytes
	data.receivedBytes = connectData.ReceivedBytes
	data.state = connectData.State
	data.success = connectData.ConnectSuccess

	return data, nil
}

func connV6BuildData(buf *bytes.Buffer) (requestMetric, error) {
	data := requestMetric{}
	connectData := connectionDataV6{}
	if err := binary.Read(buf, binary.LittleEndian, &connectData); err != nil {
		return data, err
	}

	fmt.Printf("\n----------- v6 info is: %#v ---------\n", connectData)
	data.src = connectData.SrcAddr
	data.dst = connectData.DstAddr
	data.direction = connectData.Direction
	data.dstPort = connectData.DstPort
	// data.connectionClosed = value.ConnectionClose
	// data.connectionOpened = value.ConnectionOpen
	data.sentBytes = connectData.SentBytes
	data.receivedBytes = connectData.ReceivedBytes
	data.state = connectData.State
	data.success = connectData.ConnectSuccess

	return data, nil
}

func (m *MetricController) buildWorkloadMetric(data *requestMetric) workloadMetricLabels {
	var dstAddr, srcAddr []byte
	for i := range data.dst {
		dstAddr = binary.LittleEndian.AppendUint32(dstAddr, data.dst[i])
		srcAddr = binary.LittleEndian.AppendUint32(srcAddr, data.src[i])
	}

	dstWorkload, dstIP := m.getWorkloadByAddress(restoreIPv4(dstAddr))
	srcWorkload, _ := m.getWorkloadByAddress(restoreIPv4(srcAddr))

	trafficLabels := buildWorkloadMetric(dstWorkload, srcWorkload)
	trafficLabels.destinationPodAddress = dstIP
	trafficLabels.requestProtocol = "tcp"
	trafficLabels.responseFlags = "-"
	trafficLabels.connectionSecurityPolicy = "mutual_tls"

	return trafficLabels
}

func (m *MetricController) buildServiceMetric(data *requestMetric) serviceMetricLabels {
	var dstAddr, srcAddr []byte
	for i := range data.dst {
		dstAddr = binary.LittleEndian.AppendUint32(dstAddr, data.dst[i])
		srcAddr = binary.LittleEndian.AppendUint32(srcAddr, data.src[i])
	}

	dstWorkload, _ := m.getWorkloadByAddress(restoreIPv4(dstAddr))
	srcWorkload, _ := m.getWorkloadByAddress(restoreIPv4(srcAddr))

	trafficLabels := buildServiceMetric(dstWorkload, srcWorkload, data.dstPort)
	trafficLabels.requestProtocol = "tcp"
	trafficLabels.responseFlags = "-"
	trafficLabels.connectionSecurityPolicy = "mutual_tls"

	return trafficLabels
}

func (m *MetricController) getWorkloadByAddress(address []byte) (*workloadapi.Workload, string) {
	networkAddr := cache.NetworkAddress{}
	networkAddr.Address, _ = netip.AddrFromSlice(address)
	workload := m.workloadCache.GetWorkloadByAddr(networkAddr)
	if workload == nil {
		log.Warnf("get worload from ip %v FAILED", address)
		return nil, ""
	}
	return workload, networkAddr.Address.String()
}

func buildWorkloadMetric(dstWorkload, srcWorkload *workloadapi.Workload) workloadMetricLabels {
	if dstWorkload == nil || srcWorkload == nil {
		return workloadMetricLabels{}
	}

	trafficLabels := workloadMetricLabels{}

	trafficLabels.destinationPodNamespace = dstWorkload.Namespace
	trafficLabels.destinationPodName = dstWorkload.Name
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

func buildServiceMetric(dstWorkload, srcWorkload *workloadapi.Workload, dstPort uint16) serviceMetricLabels {
	if dstWorkload == nil || srcWorkload == nil {
		return serviceMetricLabels{}
	}

	trafficLabels := serviceMetricLabels{}

	fmt.Printf("\n-=-=-=-=- %#v, %#v  -=-=-=-=\n", dstWorkload, srcWorkload)
	namespacedhost := ""
	for k, portList := range dstWorkload.Services {
		fmt.Printf("\n ****------- %#v, %#v -------*******\n", k, portList)
		for _, port := range portList.Ports {
			fmt.Printf("\n ****------- %#v -------*******\n", port)
			if port.TargetPort == uint32(dstPort) {
				namespacedhost = k
				break
			}
		}
		if namespacedhost != "" {
			break
		}
	}
	if namespacedhost == "" {
		log.Infof("can't find service correspond workload: %s", dstWorkload.Name)
	}

	svcHost := ""
	svcNamespace := ""
	if len(strings.Split(namespacedhost, "/")) != 2 {
		log.Info("get destination service host failed")
	} else {
		svcNamespace = strings.Split(namespacedhost, "/")[0]
		svcHost = strings.Split(namespacedhost, "/")[1]
	}

	trafficLabels.destinationService = svcHost
	trafficLabels.destinationServiceNamespace = svcNamespace
	trafficLabels.destinationServiceName = svcHost

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

func buildWorkloadMetricsToPrometheus(data requestMetric, labels workloadMetricLabels) {
	commonLabels := struct2map(labels)
	tcpConnectionOpenedInWorkload.With(commonLabels).Add(float64(1))
	tcpConnectionClosedInWorkload.With(commonLabels).Add(float64(1))
	if data.success != uint32(1) {
		tcpConnectionFailedInWorkload.With(commonLabels).Add(float64(1))
	}
	tcpReceivedBytesInWorkload.With(commonLabels).Add(float64(data.receivedBytes))
	tcpSentBytesInWorkload.With(commonLabels).Add(float64(data.sentBytes))
}

func buildServiceMetricsToPrometheus(data requestMetric, labels serviceMetricLabels) {
	commonLabels := struct2map(labels)
	tcpConnectionOpenedInService.With(commonLabels).Add(float64(1))
	tcpConnectionClosedInService.With(commonLabels).Add(float64(1))
	if data.success != uint32(1) {
		tcpConnectionFailedInService.With(commonLabels).Add(float64(1))
	}
	tcpReceivedBytesInService.With(commonLabels).Add(float64(data.receivedBytes))
	tcpSentBytesInService.With(commonLabels).Add(float64(data.sentBytes))
}

func struct2map(labels interface{}) map[string]string {
	if reflect.TypeOf(labels).Kind() == reflect.Struct {
		trafficLabelsMap := make(map[string]string)
		val := reflect.ValueOf(labels)
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
	} else {
		log.Error("failed to convert struct to map")
	}
	return nil
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
