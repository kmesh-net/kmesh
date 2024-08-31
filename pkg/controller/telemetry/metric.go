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
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
)

const (
	TCP_ESTABLISHED = uint32(1)
	TCP_CLOSTED     = uint32(7)

	connection_success = uint32(1)

	MSG_LEN = 112
)

var osStartTime time.Time

type MetricController struct {
	workloadCache cache.WorkloadCache
	metricCache   metricInfoCache
}

type metricInfoCache struct {
	WorkloadConnOpened        map[workloadMetricLabels]float64
	WorkloadConnClosed        map[workloadMetricLabels]float64
	WorkloadConnSentBytes     map[workloadMetricLabels]float64
	WorkloadConnReceivedBytes map[workloadMetricLabels]float64
	WorkloadConnFailed        map[workloadMetricLabels]float64
	ServiceConnOpened         map[serviceMetricLabels]float64
	ServiceConnClosed         map[serviceMetricLabels]float64
	ServiceConnSentBytes      map[serviceMetricLabels]float64
	ServiceConnReceivedBytes  map[serviceMetricLabels]float64
	ServiceConnFailed         map[serviceMetricLabels]float64
}

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
	Duration       uint64
	CloseTime      uint64
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
	Duration       uint64
	CloseTime      uint64
	State          uint32
}

type requestMetric struct {
	src           [4]uint32
	dst           [4]uint32
	srcPort       uint16
	dstPort       uint16
	direction     uint32
	receivedBytes uint32
	sentBytes     uint32
	state         uint32
	success       uint32
	duration      uint64
	closeTime     uint64
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
		metricCache:   newMetricCache(),
	}
}

func newMetricCache() metricInfoCache {
	return metricInfoCache{
		WorkloadConnOpened:        map[workloadMetricLabels]float64{},
		WorkloadConnClosed:        map[workloadMetricLabels]float64{},
		WorkloadConnSentBytes:     map[workloadMetricLabels]float64{},
		WorkloadConnReceivedBytes: map[workloadMetricLabels]float64{},
		WorkloadConnFailed:        map[workloadMetricLabels]float64{},
		ServiceConnOpened:         map[serviceMetricLabels]float64{},
		ServiceConnClosed:         map[serviceMetricLabels]float64{},
		ServiceConnSentBytes:      map[serviceMetricLabels]float64{},
		ServiceConnReceivedBytes:  map[serviceMetricLabels]float64{},
		ServiceConnFailed:         map[serviceMetricLabels]float64{},
	}
}

func (m *MetricController) Run(ctx context.Context, mapOfTcpInfo *ebpf.Map) {
	if m == nil {
		return
	}

	var err error
	osStartTime, err = getOSBootTime()
	if err != nil {
		log.Errorf("get latest os boot time for accesslog failed: %v", err)
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
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Metrics updated every 3 seconds
				time.Sleep(3 * time.Second)
				err := m.updatePrometheusMetric()
				if err != nil {
					log.Errorf("update Kmesh metrics failed: %v", err)
				}
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			data := requestMetric{}
			rec := ringbuf.Record{}
			if err := reader.ReadInto(&rec); err != nil {
				log.Errorf("ringbuf reader FAILED to read, err: %v", err)
				continue
			}
			if len(rec.RawSample) != MSG_LEN {
				log.Errorf("wrong length %v of a msg, should be %v", len(rec.RawSample), MSG_LEN)
				continue
			}

			connectType := binary.LittleEndian.Uint32(rec.RawSample)
			originInfo := rec.RawSample[unsafe.Sizeof(connectType):]
			buf := bytes.NewBuffer(originInfo)
			switch connectType {
			case constants.MSG_TYPE_IPV4:
				data, err = buildV4Metric(buf)
			case constants.MSG_TYPE_IPV6:
				data, err = buildV6Metric(buf)
			default:
				log.Errorf("get connection info failed: %v", err)
				continue
			}

			workloadLabels := m.buildWorkloadMetric(&data)
			serviceLabels, accesslog := m.buildServiceMetric(&data)

			workloadLabels.reporter = "-"
			serviceLabels.reporter = "-"
			accesslog.direction = "-"
			if data.direction == constants.INBOUND {
				workloadLabels.reporter = "destination"
				serviceLabels.reporter = "destination"
				accesslog.direction = "INBOUND"
			}
			if data.direction == constants.OUTBOUND {
				workloadLabels.reporter = "source"
				serviceLabels.reporter = "source"
				accesslog.direction = "OUTBOUND"
			}

			if data.state == TCP_CLOSTED {
				OutputAccesslog(data, accesslog)
			}
			m.buildWorkloadMetricsToPrometheus(data, workloadLabels)
			m.buildServiceMetricsToPrometheus(data, serviceLabels)
		}
	}
}

func buildV4Metric(buf *bytes.Buffer) (requestMetric, error) {
	data := requestMetric{}
	connectData := connectionDataV4{}
	if err := binary.Read(buf, binary.LittleEndian, &connectData); err != nil {
		return data, err
	}

	data.src[0] = connectData.SrcAddr
	data.dst[0] = connectData.DstAddr
	data.direction = connectData.Direction
	data.dstPort = connectData.DstPort
	data.srcPort = connectData.SrcPort

	data.sentBytes = connectData.SentBytes
	data.receivedBytes = connectData.ReceivedBytes
	data.state = connectData.State
	data.success = connectData.ConnectSuccess
	data.duration = connectData.Duration
	data.closeTime = connectData.CloseTime

	return data, nil
}

func buildV6Metric(buf *bytes.Buffer) (requestMetric, error) {
	data := requestMetric{}
	connectData := connectionDataV6{}
	if err := binary.Read(buf, binary.LittleEndian, &connectData); err != nil {
		return data, err
	}
	data.src = connectData.SrcAddr
	data.dst = connectData.DstAddr
	data.direction = connectData.Direction
	data.dstPort = connectData.DstPort
	data.srcPort = connectData.SrcPort

	data.sentBytes = connectData.SentBytes
	data.receivedBytes = connectData.ReceivedBytes
	data.state = connectData.State
	data.success = connectData.ConnectSuccess
	data.duration = connectData.Duration
	data.closeTime = connectData.CloseTime

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

func (m *MetricController) buildServiceMetric(data *requestMetric) (serviceMetricLabels, logInfo) {
	var dstAddr, srcAddr []byte
	for i := range data.dst {
		dstAddr = binary.LittleEndian.AppendUint32(dstAddr, data.dst[i])
		srcAddr = binary.LittleEndian.AppendUint32(srcAddr, data.src[i])
	}

	dstWorkload, dstIp := m.getWorkloadByAddress(restoreIPv4(dstAddr))
	srcWorkload, srcIp := m.getWorkloadByAddress(restoreIPv4(srcAddr))

	trafficLabels, accesslog := buildServiceMetric(dstWorkload, srcWorkload, data.dstPort)
	trafficLabels.requestProtocol = "tcp"
	trafficLabels.responseFlags = "-"
	trafficLabels.connectionSecurityPolicy = "mutual_tls"
	accesslog.destinationAddress = dstIp + ":" + fmt.Sprintf("%d", data.dstPort)
	accesslog.sourceAddress = srcIp + ":" + fmt.Sprintf("%d", data.srcPort)

	return trafficLabels, accesslog
}

func (m *MetricController) getWorkloadByAddress(address []byte) (*workloadapi.Workload, string) {
	networkAddr := cache.NetworkAddress{}
	networkAddr.Address, _ = netip.AddrFromSlice(address)
	workload := m.workloadCache.GetWorkloadByAddr(networkAddr)
	if workload == nil {
		return nil, ""
	}
	return workload, networkAddr.Address.String()
}

func buildWorkloadMetric(dstWorkload, srcWorkload *workloadapi.Workload) workloadMetricLabels {
	trafficLabels := workloadMetricLabels{}

	if dstWorkload != nil {
		trafficLabels.destinationPodNamespace = dstWorkload.Namespace
		trafficLabels.destinationPodName = dstWorkload.Name
		trafficLabels.destinationWorkload = dstWorkload.WorkloadName
		trafficLabels.destinationCanonicalService = dstWorkload.CanonicalName
		trafficLabels.destinationCanonicalRevision = dstWorkload.CanonicalRevision
		trafficLabels.destinationWorkloadNamespace = dstWorkload.Namespace
		trafficLabels.destinationApp = dstWorkload.CanonicalName
		trafficLabels.destinationVersion = dstWorkload.CanonicalRevision
		trafficLabels.destinationCluster = dstWorkload.ClusterId
		trafficLabels.destinationPrincipal = buildPrincipal(dstWorkload)
	}

	if srcWorkload != nil {
		trafficLabels.sourceWorkload = srcWorkload.WorkloadName
		trafficLabels.sourceCanonicalService = srcWorkload.CanonicalName
		trafficLabels.sourceCanonicalRevision = srcWorkload.CanonicalRevision
		trafficLabels.sourceWorkloadNamespace = srcWorkload.Namespace
		trafficLabels.sourceApp = srcWorkload.CanonicalName
		trafficLabels.sourceVersion = srcWorkload.CanonicalRevision
		trafficLabels.sourceCluster = srcWorkload.ClusterId
		trafficLabels.sourcePrincipal = buildPrincipal(srcWorkload)
	}

	return trafficLabels
}

func buildServiceMetric(dstWorkload, srcWorkload *workloadapi.Workload, dstPort uint16) (serviceMetricLabels, logInfo) {
	trafficLabels := serviceMetricLabels{}
	accesslog := logInfo{}

	if dstWorkload != nil {
		namespacedhost := ""
		for k, portList := range dstWorkload.Services {
			for _, port := range portList.Ports {
				if port.TargetPort == uint32(dstPort) {
					namespacedhost = k
					break
				}
			}
			if namespacedhost != "" {
				break
			}
		}

		svcHost := ""
		svcNamespace := ""
		if len(strings.Split(namespacedhost, "/")) == 2 {
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
		trafficLabels.destinationPrincipal = buildPrincipal(dstWorkload)
		trafficLabels.destinationPrincipal = buildPrincipal(dstWorkload)

		accesslog.destinationWorkload = dstWorkload.Name
		accesslog.destinationNamespace = svcNamespace
		accesslog.destinationService = svcHost
	}

	if srcWorkload != nil {
		trafficLabels.sourceWorkload = srcWorkload.WorkloadName
		trafficLabels.sourceCanonicalService = srcWorkload.CanonicalName
		trafficLabels.sourceCanonicalRevision = srcWorkload.CanonicalRevision
		trafficLabels.sourceWorkloadNamespace = srcWorkload.Namespace
		trafficLabels.sourceApp = srcWorkload.CanonicalName
		trafficLabels.sourceVersion = srcWorkload.CanonicalRevision
		trafficLabels.sourceCluster = srcWorkload.ClusterId
		trafficLabels.sourcePrincipal = buildPrincipal(srcWorkload)

		accesslog.sourceNamespace = srcWorkload.Namespace
		accesslog.sourceWorkload = srcWorkload.Name
	}

	return trafficLabels, accesslog
}

func buildPrincipal(workload *workloadapi.Workload) string {
	if workload.TrustDomain != "" && workload.ServiceAccount != "" && workload.Namespace != "" {
		return fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", workload.TrustDomain, workload.Namespace, workload.ServiceAccount)
	}
	return "-"
}

func (m *MetricController) buildWorkloadMetricsToPrometheus(data requestMetric, labels workloadMetricLabels) {
	// commonLabels := struct2map(labels)

	// if data.state == TCP_ESTABLISHED {
	// 	tcpConnectionOpenedInWorkload.With(commonLabels).Add(float64(1))
	// }
	// if data.state == TCP_CLOSTED {
	// 	tcpConnectionClosedInWorkload.With(commonLabels).Add(float64(1))
	// }
	// if data.success != connection_success {
	// 	tcpConnectionFailedInWorkload.With(commonLabels).Add(float64(1))
	// }
	// tcpReceivedBytesInWorkload.With(commonLabels).Add(float64(data.receivedBytes))
	// tcpSentBytesInWorkload.With(commonLabels).Add(float64(data.sentBytes))
	_, ok := m.metricCache.WorkloadConnReceivedBytes[labels]
	if ok {
		if data.state == TCP_ESTABLISHED {
			m.metricCache.WorkloadConnOpened[labels] = m.metricCache.WorkloadConnOpened[labels] + 1
		}
		if data.state == TCP_CLOSTED {
			m.metricCache.WorkloadConnClosed[labels] = m.metricCache.WorkloadConnClosed[labels] + 1
		}
		if data.success != connection_success {
			m.metricCache.WorkloadConnFailed[labels] = m.metricCache.WorkloadConnFailed[labels] + 1
		}
		m.metricCache.WorkloadConnReceivedBytes[labels] = m.metricCache.WorkloadConnReceivedBytes[labels] + float64(data.receivedBytes)
		m.metricCache.WorkloadConnSentBytes[labels] = m.metricCache.WorkloadConnSentBytes[labels] + float64(data.sentBytes)
	} else {
		if data.state == TCP_ESTABLISHED {
			m.metricCache.WorkloadConnOpened[labels] = 1
		}
		if data.state == TCP_CLOSTED {
			m.metricCache.WorkloadConnClosed[labels] = 1
		}
		if data.success != connection_success {
			m.metricCache.WorkloadConnFailed[labels] = 1
		}
		m.metricCache.WorkloadConnReceivedBytes[labels] = float64(data.receivedBytes)
		m.metricCache.WorkloadConnSentBytes[labels] = float64(data.sentBytes)
	}
}

func (m *MetricController) buildServiceMetricsToPrometheus(data requestMetric, labels serviceMetricLabels) {
	// commonLabels := struct2map(labels)

	// if data.state == TCP_ESTABLISHED {
	// 	tcpConnectionOpenedInService.With(commonLabels).Add(float64(1))
	// }
	// if data.state == TCP_CLOSTED {
	// 	tcpConnectionClosedInService.With(commonLabels).Add(float64(1))
	// }
	// if data.success != uint32(1) {
	// 	tcpConnectionFailedInService.With(commonLabels).Add(float64(1))
	// }
	// tcpReceivedBytesInService.With(commonLabels).Add(float64(data.receivedBytes))
	// tcpSentBytesInService.With(commonLabels).Add(float64(data.sentBytes))
	_, ok := m.metricCache.ServiceConnReceivedBytes[labels]
	if ok {
		if data.state == TCP_ESTABLISHED {
			m.metricCache.ServiceConnOpened[labels] = m.metricCache.ServiceConnOpened[labels] + 1
		}
		if data.state == TCP_CLOSTED {
			m.metricCache.ServiceConnClosed[labels] = m.metricCache.ServiceConnClosed[labels] + 1
		}
		if data.success != connection_success {
			m.metricCache.ServiceConnFailed[labels] = m.metricCache.ServiceConnFailed[labels] + 1
		}
		m.metricCache.ServiceConnReceivedBytes[labels] = m.metricCache.ServiceConnReceivedBytes[labels] + float64(data.receivedBytes)
		m.metricCache.ServiceConnSentBytes[labels] = m.metricCache.ServiceConnSentBytes[labels] + float64(data.sentBytes)
	} else {
		if data.state == TCP_ESTABLISHED {
			m.metricCache.ServiceConnOpened[labels] = 1
		}
		if data.state == TCP_CLOSTED {
			m.metricCache.ServiceConnClosed[labels] = 1
		}
		if data.success != connection_success {
			m.metricCache.ServiceConnFailed[labels] = 1
		}
		m.metricCache.ServiceConnReceivedBytes[labels] = float64(data.receivedBytes)
		m.metricCache.ServiceConnSentBytes[labels] = float64(data.sentBytes)
	}
}

func (m *MetricController) updatePrometheusMetric() error {
	val := reflect.ValueOf(m.metricCache)
	typ := reflect.TypeOf(m.metricCache)

	// check if has pointer in struct
	if typ.Kind() == reflect.Ptr {
		val = val.Elem()
		typ = typ.Elem()

	}
	num := val.NumField()
	for i := 0; i < num; i++ {
		sType := typ.Field(i)
		sVal := val.Field(i).Interface()
		workloadMap, isWorkload := sVal.(map[workloadMetricLabels]float64)
		// fmt.Printf("\n ------- %v, \n%v -------- \n", workloadMap, isWorkload)
		if isWorkload {
			for k, v := range workloadMap {
				name := sType.Name
				commonLabels := struct2map(k)
				// fmt.Printf("name is %v, value is: %v", name, v)
				switch name {
				case "WorkloadConnOpened":
					tcpConnectionOpenedInWorkload.With(commonLabels).Set(float64(v))
				case "WorkloadConnClosed":
					tcpConnectionClosedInWorkload.With(commonLabels).Set(float64(v))
				case "WorkloadConnSentBytes":
					tcpSentBytesInWorkload.With(commonLabels).Set(float64(v))
				case "WorkloadConnReceivedBytes":
					tcpReceivedBytesInWorkload.With(commonLabels).Set(float64(v))
				case "WorkloadConnFailed":
					tcpConnectionFailedInWorkload.With(commonLabels).Set(float64(v))
				}
			}
		}
		serviceMap, isService := sVal.(map[serviceMetricLabels]float64)
		// fmt.Printf("\n ------- %v, \n%v -------- \n", serviceMap, isService)
		if isService {
			for k, v := range serviceMap {
				name := sType.Name
				commonLabels := struct2map(k)
				switch name {
				case "ServiceConnOpened":
					tcpConnectionOpenedInService.With(commonLabels).Set(float64(v))
				case "ServiceConnClosed":
					tcpConnectionClosedInService.With(commonLabels).Set(float64(v))
				case "ServiceConnSentBytes":
					tcpSentBytesInService.With(commonLabels).Set(float64(v))
				case "ServiceConnReceivedBytes":
					tcpReceivedBytesInService.With(commonLabels).Set(float64(v))
				case "ServiceConnFailed":
					tcpConnectionFailedInService.With(commonLabels).Set(float64(v))
				}
			}
		}
		if !isWorkload && !isService {
			return fmt.Errorf("get metricCahce data failed")
		}
	}
	return nil
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
