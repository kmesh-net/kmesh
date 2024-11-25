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
	"sync"
	"sync/atomic"
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

	metricFlushInterval = 5 * time.Second
)

var osStartTime time.Time

type MetricController struct {
	EnableAccesslog     atomic.Bool
	workloadCache       cache.WorkloadCache
	workloadMetricCache map[workloadMetricLabels]*workloadMetricInfo
	serviceMetricCache  map[serviceMetricLabels]*serviceMetricInfo
	mutex               sync.RWMutex
}

type workloadMetricInfo struct {
	WorkloadConnOpened        float64
	WorkloadConnClosed        float64
	WorkloadConnSentBytes     float64
	WorkloadConnReceivedBytes float64
	WorkloadConnFailed        float64
}

type serviceMetricInfo struct {
	ServiceConnOpened        float64
	ServiceConnClosed        float64
	ServiceConnSentBytes     float64
	ServiceConnReceivedBytes float64
	ServiceConnFailed        float64
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

func NewMetric(workloadCache cache.WorkloadCache, enableAccesslog bool) *MetricController {
	m := &MetricController{
		workloadCache:       workloadCache,
		workloadMetricCache: map[workloadMetricLabels]*workloadMetricInfo{},
		serviceMetricCache:  map[serviceMetricLabels]*serviceMetricInfo{},
	}
	m.EnableAccesslog.Store(enableAccesslog)
	return m
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
				// Metrics updated every 5 seconds
				time.Sleep(metricFlushInterval)
				m.updatePrometheusMetric()
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
			if data.state == TCP_CLOSTED && m.EnableAccesslog.Load() {
				OutputAccesslog(data, accesslog)
			}
			m.mutex.Lock()
			m.updateWorkloadMetricCache(data, workloadLabels)
			m.updateServiceMetricCache(data, serviceLabels)
			m.mutex.Unlock()
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

	if srcWorkload == nil {
		return workloadMetricLabels{}
	}

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
		return nil, networkAddr.Address.String()
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
	accesslog := logInfo{
		direction:            "-",
		sourceAddress:        "-",
		sourceWorkload:       "-",
		sourceNamespace:      "-",
		destinationAddress:   "-",
		destinationService:   "-",
		destinationWorkload:  "-",
		destinationNamespace: "-",
	}

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
		if svcNamespace != "" {
			accesslog.destinationNamespace = svcNamespace
		}
		if svcHost != "" {
			accesslog.destinationService = svcHost
		}
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

func (m *MetricController) updateWorkloadMetricCache(data requestMetric, labels workloadMetricLabels) {
	v, ok := m.workloadMetricCache[labels]
	if ok {
		if data.state == TCP_ESTABLISHED {
			v.WorkloadConnOpened = v.WorkloadConnOpened + 1
		}
		if data.state == TCP_CLOSTED {
			v.WorkloadConnClosed = v.WorkloadConnClosed + 1
		}
		if data.success != connection_success {
			v.WorkloadConnFailed = v.WorkloadConnFailed + 1
		}
		v.WorkloadConnReceivedBytes = v.WorkloadConnReceivedBytes + float64(data.receivedBytes)
		v.WorkloadConnSentBytes = v.WorkloadConnSentBytes + float64(data.sentBytes)
	} else {
		newWorkloadMetricInfo := workloadMetricInfo{}
		if data.state == TCP_ESTABLISHED {
			newWorkloadMetricInfo.WorkloadConnOpened = 1
		}
		if data.state == TCP_CLOSTED {
			newWorkloadMetricInfo.WorkloadConnClosed = 1
		}
		if data.success != connection_success {
			newWorkloadMetricInfo.WorkloadConnFailed = 1
		}
		newWorkloadMetricInfo.WorkloadConnReceivedBytes = float64(data.receivedBytes)
		newWorkloadMetricInfo.WorkloadConnSentBytes = float64(data.sentBytes)
		m.workloadMetricCache[labels] = &newWorkloadMetricInfo
	}
}

func (m *MetricController) updateServiceMetricCache(data requestMetric, labels serviceMetricLabels) {
	v, ok := m.serviceMetricCache[labels]
	if ok {
		if data.state == TCP_ESTABLISHED {
			v.ServiceConnOpened = v.ServiceConnOpened + 1
		}
		if data.state == TCP_CLOSTED {
			v.ServiceConnClosed = v.ServiceConnClosed + 1
		}
		if data.success != connection_success {
			v.ServiceConnFailed = v.ServiceConnFailed + 1
		}
		v.ServiceConnReceivedBytes = v.ServiceConnReceivedBytes + float64(data.receivedBytes)
		v.ServiceConnSentBytes = v.ServiceConnSentBytes + float64(data.sentBytes)
	} else {
		newServiceMetricInfo := serviceMetricInfo{}
		if data.state == TCP_ESTABLISHED {
			newServiceMetricInfo.ServiceConnOpened = 1
		}
		if data.state == TCP_CLOSTED {
			newServiceMetricInfo.ServiceConnClosed = 1
		}
		if data.success != connection_success {
			newServiceMetricInfo.ServiceConnFailed = 1
		}
		newServiceMetricInfo.ServiceConnReceivedBytes = float64(data.receivedBytes)
		newServiceMetricInfo.ServiceConnSentBytes = float64(data.sentBytes)
		m.serviceMetricCache[labels] = &newServiceMetricInfo
	}
}

func (m *MetricController) updatePrometheusMetric() {
	m.mutex.Lock()
	workloadInfoCache := m.workloadMetricCache
	serviceInfoCache := m.serviceMetricCache
	m.workloadMetricCache = map[workloadMetricLabels]*workloadMetricInfo{}
	m.serviceMetricCache = map[serviceMetricLabels]*serviceMetricInfo{}
	m.mutex.Unlock()

	for k, v := range workloadInfoCache {
		workloadLabels := struct2map(k)
		tcpConnectionOpenedInWorkload.With(workloadLabels).Add(v.WorkloadConnOpened)
		tcpConnectionClosedInWorkload.With(workloadLabels).Add(v.WorkloadConnClosed)
		tcpSentBytesInWorkload.With(workloadLabels).Add(v.WorkloadConnSentBytes)
		tcpReceivedBytesInWorkload.With(workloadLabels).Add(v.WorkloadConnReceivedBytes)
		tcpConnectionFailedInWorkload.With(workloadLabels).Add(v.WorkloadConnFailed)
	}

	for k, v := range serviceInfoCache {
		serviceLabels := struct2map(k)
		tcpConnectionOpenedInService.With(serviceLabels).Add(v.ServiceConnOpened)
		tcpConnectionClosedInService.With(serviceLabels).Add(v.ServiceConnClosed)
		tcpConnectionFailedInService.With(serviceLabels).Add(v.ServiceConnFailed)
		tcpReceivedBytesInService.With(serviceLabels).Add(v.ServiceConnReceivedBytes)
		tcpSentBytesInService.With(serviceLabels).Add(v.ServiceConnSentBytes)
	}

	// delete metrics
	deleteLock.Lock()
	// Creating a copy reduces the amount of time spent adding locks in the programme
	workloadReplica := deleteWorkload
	deleteWorkload = nil
	serviceReplica := deleteService
	deleteService = nil
	deleteLock.Unlock()

	for i := 0; i < len(workloadReplica); i++ {
		deleteWorkloadMetricInPrometheus(workloadReplica[i])
	}
	for i := 0; i < len(serviceReplica); i++ {
		deleteServiceMetricInPrometheus(serviceReplica[i])
	}
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
