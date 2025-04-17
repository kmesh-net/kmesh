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

	MSG_LEN = 96

	metricFlushInterval = 5 * time.Second

	DEFAULT_UNKNOWN = "-"
)

var osStartTime time.Time

var TCP_STATES = map[uint32]string{
	1:  "BPF_TCP_ESTABLISHED",
	2:  "BPF_TCP_SYN_SENT",
	3:  "BPF_TCP_SYN_RECV",
	4:  "BPF_TCP_FIN_WAIT1",
	5:  "BPF_TCP_FIN_WAIT2",
	6:  "BPF_TCP_TIME_WAIT",
	7:  "BPF_TCP_CLOSE",
	8:  "BPF_TCP_CLOSE_WAIT",
	9:  "BPF_TCP_LAST_ACK",
	10: "BPF_TCP_LISTEN",
	11: "BPF_TCP_CLOSING",
	12: "BPF_TCP_NEW_SYN_RECV",
	13: "BPF_TCP_MAX_STATES",
}

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
	WorkloadConnTotalRetrans  float64
	WorkloadConnPacketLost    float64
}

type serviceMetricInfo struct {
	ServiceConnOpened        float64
	ServiceConnClosed        float64
	ServiceConnSentBytes     float64
	ServiceConnReceivedBytes float64
	ServiceConnFailed        float64
}

type statistics struct {
	SentBytes      uint32
	ReceivedBytes  uint32
	ConnectSuccess uint32
	Direction      uint32
	State          uint32 // TCP state ex: BPF_TCP_ESTABLISHED
	Duration       uint64 // duration of the connection till now
	StartTime      uint64 // time when the connection is established
	LastReportTime uint64 // time when the metric is reported
	Protocol       uint32
	SRttTime       uint32 // smoothed RTT
	RttMin         uint32 // minimum RTT
	Retransmits    uint32 // total retransmits
	LostPackets    uint32 // total lost packets
}

// connectionDataV4 read from ebpf km_tcp_probe ringbuf and padding with `_`
type connectionDataV4 struct {
	SrcAddr      uint32
	DstAddr      uint32
	SrcPort      uint16
	DstPort      uint16
	_            [6]uint32
	OriginalAddr uint32
	OriginalPort uint16
	_            [7]uint16
	statistics
	_ uint32
}

// connectionDataV6 read from ebpf km_tcp_probe ringbuf and padding with `_`
type connectionDataV6 struct {
	SrcAddr      [4]uint32
	DstAddr      [4]uint32
	SrcPort      uint16
	DstPort      uint16
	OriginalAddr [4]uint32
	OriginalPort uint16
	_            uint16
	statistics
	_ uint32
}

type connMetric struct {
	receivedBytes uint32 // total bytes received till now
	sentBytes     uint32 // total bytes sent till now
	totalRetrans  uint32 // total retransmits till now
	packetLost    uint32 // total packets lost till now
}

type connectionSrcDst struct {
	src     [4]uint32
	dst     [4]uint32
	srcPort uint16
	dstPort uint16
}

type requestMetric struct {
	conSrcDstInfo  connectionSrcDst
	origDstAddr    [4]uint32
	origDstPort    uint16
	direction      uint32
	receivedBytes  uint32 // total bytes received after previous report
	sentBytes      uint32 // total bytes sent after previous report
	state          uint32
	success        uint32
	duration       uint64
	startTime      uint64
	lastReportTime uint64
	srtt           uint32
	minRtt         uint32
	totalRetrans   uint32 // total retransmits after previous report
	packetLost     uint32 // total packets lost after previous report
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

	requestProtocol string
	// TODO: responseFlags is not used for now
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

	requestProtocol string
	// TODO: responseFlags is not used for now
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
		log.Errorf("open km_tcp_probe ringbuf map FAILED, err: %v", err)
		return
	}

	defer func() {
		if err := reader.Close(); err != nil {
			log.Errorf("ringbuf reader Close FAILED, err: %v", err)
		}
	}()

	tcp_conns := make(map[connectionSrcDst]connMetric)

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

			// len(rec.RawSample) = 128
			if len(rec.RawSample) != int(unsafe.Sizeof(connectionDataV4{}))-int(8) {
				log.Errorf("wrong length %v of a msg, should be %v", len(rec.RawSample), int(unsafe.Sizeof(connectionDataV4{}))-int(8))
				continue
			}
			connectType := binary.LittleEndian.Uint32(rec.RawSample)
			originInfo := rec.RawSample[unsafe.Sizeof(connectType):]
			buf := bytes.NewBuffer(originInfo)
			switch connectType {
			case constants.MSG_TYPE_IPV4:
				data, err = buildV4Metric(buf, tcp_conns)
				if err != nil {
					log.Errorf("get connectionV4 info failed: %v", err)
					continue
				}
			case constants.MSG_TYPE_IPV6:
				data, err = buildV6Metric(buf, tcp_conns)
				if err != nil {
					log.Errorf("get connectionV6 info failed: %v", err)
					continue
				}
			default:
				log.Errorf("get connection info failed: %v", err)
				continue
			}

			workloadLabels := workloadMetricLabels{}
			serviceLabels, accesslog := m.buildServiceMetric(&data)
			if m.EnableWorkloadMetric.Load() {
				workloadLabels = m.buildWorkloadMetric(&data)
			}

			if m.EnableAccesslog.Load() {
				// accesslogs at start of connection, at interval of 5 sec during connection lifecycle and at close of connection
				OutputAccesslog(data, tcp_conns[data.conSrcDstInfo], accesslog)
			}

			if data.state == TCP_CLOSTED {
				delete(tcp_conns, data.conSrcDstInfo)
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

func buildV4Metric(buf *bytes.Buffer, tcp_conns map[connectionSrcDst]connMetric) (requestMetric, error) {
	data := requestMetric{}
	connectData := connectionDataV4{}

	if err := binary.Read(buf, binary.LittleEndian, &connectData); err != nil {
		return data, err
	}

	data.conSrcDstInfo.src[0] = connectData.SrcAddr
	data.conSrcDstInfo.dst[0] = connectData.DstAddr
	data.direction = connectData.Direction
	data.conSrcDstInfo.dstPort = connectData.DstPort
	data.conSrcDstInfo.srcPort = connectData.SrcPort

	// original addr is 0 indicates the connection is
	// workload-type or and not redirected,
	// so we just take from the actual destination
	if connectData.OriginalAddr == 0 {
		data.origDstAddr[0] = data.conSrcDstInfo.dst[0]
		data.origDstPort = data.conSrcDstInfo.dstPort
	} else {
		data.origDstAddr[0] = connectData.OriginalAddr
		data.origDstPort = connectData.OriginalPort
	}

	data.sentBytes = connectData.SentBytes - tcp_conns[data.conSrcDstInfo].sentBytes
	data.receivedBytes = connectData.ReceivedBytes - tcp_conns[data.conSrcDstInfo].receivedBytes
	data.state = connectData.State
	data.success = connectData.ConnectSuccess
	data.duration = connectData.Duration
	data.startTime = connectData.StartTime
	data.lastReportTime = connectData.LastReportTime
	data.srtt = connectData.statistics.SRttTime
	data.minRtt = connectData.statistics.RttMin
	data.totalRetrans = connectData.statistics.Retransmits - tcp_conns[data.conSrcDstInfo].totalRetrans
	data.packetLost = connectData.statistics.LostPackets - tcp_conns[data.conSrcDstInfo].packetLost
	tcp_conns[data.conSrcDstInfo] = connMetric{
		receivedBytes: connectData.ReceivedBytes,
		sentBytes:     connectData.SentBytes,
		totalRetrans:  connectData.statistics.Retransmits,
		packetLost:    connectData.statistics.LostPackets,
	}

	return data, nil
}

func buildV6Metric(buf *bytes.Buffer, tcp_conns map[connectionSrcDst]connMetric) (requestMetric, error) {
	data := requestMetric{}
	connectData := connectionDataV6{}
	if err := binary.Read(buf, binary.LittleEndian, &connectData); err != nil {
		return data, err
	}
	data.conSrcDstInfo.src = connectData.SrcAddr
	data.conSrcDstInfo.dst = connectData.DstAddr
	data.direction = connectData.Direction
	data.conSrcDstInfo.dstPort = connectData.DstPort
	data.conSrcDstInfo.srcPort = connectData.SrcPort

	// original addr is 0 indicates the connection is
	// workload-type or and not redirected,
	// so we just take from the actual destination
	if !isOrigDstSet(connectData.OriginalAddr) {
		data.origDstAddr = data.conSrcDstInfo.dst
		data.origDstPort = data.conSrcDstInfo.dstPort
	} else {
		data.origDstAddr = connectData.OriginalAddr
		data.origDstPort = connectData.OriginalPort
	}

	data.sentBytes = connectData.SentBytes - tcp_conns[data.conSrcDstInfo].sentBytes
	data.receivedBytes = connectData.ReceivedBytes - tcp_conns[data.conSrcDstInfo].receivedBytes
	data.state = connectData.State
	data.success = connectData.ConnectSuccess
	data.duration = connectData.Duration
	data.startTime = connectData.StartTime
	data.lastReportTime = connectData.LastReportTime
	data.srtt = connectData.statistics.SRttTime
	data.minRtt = connectData.statistics.RttMin
	data.totalRetrans = connectData.statistics.Retransmits - tcp_conns[data.conSrcDstInfo].totalRetrans
	data.packetLost = connectData.statistics.LostPackets - tcp_conns[data.conSrcDstInfo].packetLost
	tcp_conns[data.conSrcDstInfo] = connMetric{
		receivedBytes: connectData.ReceivedBytes,
		sentBytes:     connectData.SentBytes,
		totalRetrans:  connectData.statistics.Retransmits,
		packetLost:    connectData.statistics.LostPackets,
	}

	return data, nil
}

func (m *MetricController) buildWorkloadMetric(data *requestMetric) workloadMetricLabels {
	var dstAddr, srcAddr []byte
	for i := range data.conSrcDstInfo.dst {
		dstAddr = binary.LittleEndian.AppendUint32(dstAddr, data.conSrcDstInfo.dst[i])
		srcAddr = binary.LittleEndian.AppendUint32(srcAddr, data.conSrcDstInfo.src[i])
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

	switch data.direction {
	case constants.INBOUND:
		trafficLabels.reporter = "destination"
	case constants.OUTBOUND:
		trafficLabels.reporter = "source"
	}

	return *trafficLabels
}

// guessWorkloadService find the first service of the workload that matches the destination port
func (m *MetricController) guessWorkloadService(workload *workloadapi.Workload, targetPort uint32) *workloadapi.Service {
	if workload == nil {
		return nil
	}
	namespacedhost := ""
	for k, portList := range workload.Services {
		for _, port := range portList.Ports {
			if port.TargetPort == targetPort {
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
		for host := range workload.Services {
			if host != "" {
				namespacedhost = host
				break
			}
		}
	}

	return m.serviceCache.GetService(namespacedhost)
}

func (m *MetricController) getServiceByAddress(address []byte) (*workloadapi.Service, string) {
	networkAddr := cache.NetworkAddress{}
	networkAddr.Address, _ = netip.AddrFromSlice(address)
	var svc *workloadapi.Service
	if svc = m.serviceCache.GetServiceByAddr(networkAddr); svc != nil {
		return svc, networkAddr.Address.String()
	}
	return nil, ""
}

func (m *MetricController) fetchOriginalService(address []byte, port uint32) *workloadapi.Service {
	// if destination is service-type, we just return
	svc, _ := m.getServiceByAddress(address)
	if svc != nil {
		return svc
	}
	// else if it is workload-type, we guess the destination service
	wld, wldAddr := m.getWorkloadByAddress(address)
	dstSvc := m.guessWorkloadService(wld, port)
	// when dst svc not found, we use orig dst workload addr as its hostname, if exists
	if dstSvc == nil && wld != nil {
		dstSvc = &workloadapi.Service{
			Hostname:  wldAddr,
			Namespace: wld.Namespace,
		}
	}
	return dstSvc
}

func (m *MetricController) buildServiceMetric(data *requestMetric) (serviceMetricLabels, logInfo) {
	var dstAddr, srcAddr, origAddr []byte
	for i := range data.conSrcDstInfo.dst {
		dstAddr = binary.LittleEndian.AppendUint32(dstAddr, data.conSrcDstInfo.dst[i])
		srcAddr = binary.LittleEndian.AppendUint32(srcAddr, data.conSrcDstInfo.src[i])
		origAddr = binary.LittleEndian.AppendUint32(origAddr, data.origDstAddr[i])
	}

	dstWorkload, dstIp := m.getWorkloadByAddress(restoreIPv4(dstAddr))
	srcWorkload, srcIp := m.getWorkloadByAddress(restoreIPv4(srcAddr))

	dstService := m.fetchOriginalService(restoreIPv4(origAddr), uint32(data.origDstPort))
	// if dstService not found, we use the address as hostname for metrics
	if dstService == nil {
		dstService = &workloadapi.Service{
			Hostname: dstIp,
		}
	}

	trafficLabels := NewServiceMetricLabel()
	trafficLabels.withSource(srcWorkload).withDestination(dstWorkload).withDestinationService(dstService)
	trafficLabels.requestProtocol = "tcp"
	trafficLabels.connectionSecurityPolicy = "mutual_tls"

	accesslog := NewLogInfo()
	accesslog.withSource(srcWorkload).withDestination(dstWorkload).withDestinationService(dstService)
	accesslog.destinationAddress = dstIp + ":" + fmt.Sprintf("%d", data.conSrcDstInfo.dstPort)
	accesslog.sourceAddress = srcIp + ":" + fmt.Sprintf("%d", data.conSrcDstInfo.srcPort)

	switch data.direction {
	case constants.INBOUND:
		trafficLabels.reporter = "destination"
		accesslog.direction = "INBOUND"
	case constants.OUTBOUND:
		trafficLabels.reporter = "source"
		accesslog.direction = "OUTBOUND"
	}

	accesslog.state = TCP_STATES[data.state]
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
		v.WorkloadConnTotalRetrans = v.WorkloadConnTotalRetrans + float64(data.totalRetrans)
		v.WorkloadConnPacketLost = v.WorkloadConnPacketLost + float64(data.packetLost)
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
		newWorkloadMetricInfo.WorkloadConnTotalRetrans = float64(data.totalRetrans)
		newWorkloadMetricInfo.WorkloadConnPacketLost = float64(data.packetLost)
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
		tcpConnectionTotalRetransInWorkload.With(workloadLabels).Add(v.WorkloadConnTotalRetrans)
		tcpConnectionPacketLostInWorkload.With(workloadLabels).Add(v.WorkloadConnPacketLost)
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

func isOrigDstSet(addr [4]uint32) bool {
	for _, v := range addr {
		if v != 0 {
			return true
		}
	}
	return false
}
