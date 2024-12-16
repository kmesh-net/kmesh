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

	DEFAULT_UNKNOWN = "-"
)

var osStartTime time.Time

type MetricController struct {
	EnableAccesslog      atomic.Bool
	EnableMonitoring     atomic.Bool
	EnableWorkloadMetric atomic.Bool
	workloadCache        cache.WorkloadCache
	serviceCache         cache.ServiceCache
	workloadMetricCache  map[workloadMetricLabels]*workloadMetricInfo
	serviceMetricCache   map[serviceMetricLabels]*serviceMetricInfo
	mutex                sync.RWMutex
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

func NewServiceMetricLabel() *serviceMetricLabels {
	return &serviceMetricLabels{}
}

func NewWorkloadMetricLabel() *workloadMetricLabels {
	return &workloadMetricLabels{}
}

func (w *workloadMetricLabels) withSource(workload *workloadapi.Workload) *workloadMetricLabels {
	if workload == nil {
		return w
	}
	w.sourceWorkload = workload.GetWorkloadName()
	w.sourceCanonicalService = workload.GetCanonicalName()
	w.sourceCanonicalRevision = workload.GetCanonicalRevision()
	w.sourceWorkloadNamespace = workload.GetNamespace()
	w.sourceApp = workload.GetCanonicalName()
	w.sourceVersion = workload.GetCanonicalRevision()
	w.sourceCluster = workload.GetClusterId()
	w.sourcePrincipal = buildPrincipal(workload)
	return w
}

func (w *workloadMetricLabels) withDestination(workload *workloadapi.Workload) *workloadMetricLabels {
	if workload == nil {
		return w
	}
	w.destinationPodNamespace = workload.GetNamespace()
	w.destinationPodName = workload.GetName()
	w.destinationWorkload = workload.GetWorkloadName()
	w.destinationCanonicalService = workload.GetCanonicalName()
	w.destinationCanonicalRevision = workload.GetCanonicalRevision()
	w.destinationWorkloadNamespace = workload.GetNamespace()
	w.destinationApp = workload.GetCanonicalName()
	w.destinationVersion = workload.GetCanonicalRevision()
	w.destinationCluster = workload.GetClusterId()
	w.destinationPrincipal = buildPrincipal(workload)
	return w
}

func (s *serviceMetricLabels) withSource(workload *workloadapi.Workload) *serviceMetricLabels {
	if workload == nil {
		return s
	}
	s.sourceWorkload = workload.GetWorkloadName()
	s.sourceCanonicalService = workload.GetCanonicalName()
	s.sourceCanonicalRevision = workload.GetCanonicalRevision()
	s.sourceWorkloadNamespace = workload.GetNamespace()
	s.sourceApp = workload.GetCanonicalName()
	s.sourceVersion = workload.GetCanonicalRevision()
	s.sourceCluster = workload.GetClusterId()
	s.sourcePrincipal = buildPrincipal(workload)
	return s
}

func (s *serviceMetricLabels) withDestinationService(service *workloadapi.Service) *serviceMetricLabels {
	if service == nil {
		return s
	}
	s.destinationService = service.GetHostname()
	s.destinationServiceName = service.GetName()
	s.destinationServiceNamespace = service.GetNamespace()
	return s
}

func (s *serviceMetricLabels) withDestination(workload *workloadapi.Workload) *serviceMetricLabels {
	if workload == nil {
		return s
	}
	s.destinationWorkload = workload.GetWorkloadName()
	s.destinationCanonicalService = workload.GetCanonicalName()
	s.destinationCanonicalRevision = workload.GetCanonicalRevision()
	s.destinationWorkloadNamespace = workload.GetNamespace()
	s.destinationApp = workload.GetCanonicalName()
	s.destinationVersion = workload.GetCanonicalRevision()
	s.destinationCluster = workload.GetClusterId()
	s.destinationPrincipal = buildPrincipal(workload)
	return s
}

func NewMetric(workloadCache cache.WorkloadCache, serviceCache cache.ServiceCache, enableMonitoring bool) *MetricController {
	m := &MetricController{
		workloadCache:       workloadCache,
		serviceCache:        serviceCache,
		workloadMetricCache: map[workloadMetricLabels]*workloadMetricInfo{},
		serviceMetricCache:  map[serviceMetricLabels]*serviceMetricInfo{},
	}
	m.EnableMonitoring.Store(enableMonitoring)
	m.EnableAccesslog.Store(false)
	m.EnableWorkloadMetric.Store(false)
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
			if !m.EnableMonitoring.Load() {
				continue
			}
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

			workloadLabels := workloadMetricLabels{}
			serviceLabels, accesslog := m.buildServiceMetric(&data)
			if m.EnableWorkloadMetric.Load() {
				workloadLabels = m.buildWorkloadMetric(&data)
			}

			if data.state == TCP_CLOSTED && m.EnableAccesslog.Load() {
				OutputAccesslog(data, accesslog)
			}

			m.mutex.Lock()
			if m.EnableWorkloadMetric.Load() {
				m.updateWorkloadMetricCache(data, workloadLabels)
			}
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

	trafficLabels := NewWorkloadMetricLabel()
	trafficLabels.withSource(srcWorkload).withDestination(dstWorkload)

	trafficLabels.destinationPodAddress = dstIP
	trafficLabels.requestProtocol = "tcp"
	trafficLabels.connectionSecurityPolicy = "mutual_tls"
	trafficLabels.reporter = DEFAULT_UNKNOWN

	switch data.direction {
	case constants.INBOUND:
		trafficLabels.reporter = "destination"
	case constants.OUTBOUND:
		trafficLabels.reporter = "source"
	}

	return *trafficLabels
}

func (m *MetricController) buildServiceMetric(data *requestMetric) (serviceMetricLabels, logInfo) {
	var dstAddr, srcAddr []byte
	for i := range data.dst {
		dstAddr = binary.LittleEndian.AppendUint32(dstAddr, data.dst[i])
		srcAddr = binary.LittleEndian.AppendUint32(srcAddr, data.src[i])
	}

	dstWorkload, dstIp := m.getWorkloadByAddress(restoreIPv4(dstAddr))
	srcWorkload, srcIp := m.getWorkloadByAddress(restoreIPv4(srcAddr))

	namespacedhost := ""
	if dstWorkload != nil {
		for k, portList := range dstWorkload.Services {
			for _, port := range portList.Ports {
				if port.TargetPort == uint32(data.dstPort) {
					namespacedhost = k
					break
				}
			}
			if namespacedhost != "" {
				break
			}
		}
		// Handling a Headless Service that does not specify a target port
		if namespacedhost == "" {
			for host := range dstWorkload.Services {
				if host != "" {
					namespacedhost = host
					break
				}
			}
		}
	}

	dstService := m.serviceCache.GetService(namespacedhost)
	// when service not found, we use the address as hostname for metrics
	if dstService == nil {
		dstService = &workloadapi.Service{
			Hostname: dstIp,
		}
	}

	trafficLabels := NewServiceMetricLabel()
	trafficLabels.withSource(srcWorkload).withDestination(dstWorkload).withDestinationService(dstService)

	trafficLabels.requestProtocol = "tcp"
	trafficLabels.connectionSecurityPolicy = "mutual_tls"
	trafficLabels.reporter = DEFAULT_UNKNOWN

	accesslog := NewLogInfo()
	accesslog.withSource(srcWorkload).withDestination(dstWorkload).withDestinationService(dstService)

	accesslog.destinationAddress = dstIp + ":" + fmt.Sprintf("%d", data.dstPort)
	accesslog.sourceAddress = srcIp + ":" + fmt.Sprintf("%d", data.srcPort)

	switch data.direction {
	case constants.INBOUND:
		trafficLabels.reporter = "destination"
		accesslog.direction = "INBOUND"
	case constants.OUTBOUND:
		trafficLabels.reporter = "source"
		accesslog.direction = "OUTBOUND"
	}

	return *trafficLabels, *accesslog
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

func buildPrincipal(workload *workloadapi.Workload) string {
	if workload.TrustDomain != "" && workload.ServiceAccount != "" && workload.Namespace != "" {
		return fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", workload.TrustDomain, workload.Namespace, workload.ServiceAccount)
	}
	return DEFAULT_UNKNOWN
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
				trafficLabelsMap[labelsMap[fieldInfo.Name]] = DEFAULT_UNKNOWN
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
