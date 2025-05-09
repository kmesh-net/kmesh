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
	TCP_CLOSED      = uint32(7)

	connection_success = uint32(1)

	MSG_LEN = 96

	metricFlushInterval = 5 * time.Second

	DEFAULT_UNKNOWN = "-"

	LONG_CONN_METRIC_THRESHOLD = uint64(5 * time.Second)
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
	EnableAccesslog        atomic.Bool
	EnableMonitoring       atomic.Bool
	EnableWorkloadMetric   atomic.Bool
	EnableConnectionMetric atomic.Bool
	workloadCache          cache.WorkloadCache
	serviceCache           cache.ServiceCache
	workloadMetricCache    map[workloadMetricLabels]*workloadMetricInfo
	serviceMetricCache     map[serviceMetricLabels]*serviceMetricInfo
	connectionMetricCache  map[connectionMetricLabels]*connectionMetricInfo
	mutex                  sync.RWMutex
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

type connectionMetricInfo struct {
	ConnSentBytes     float64
	ConnReceivedBytes float64
	ConnTotalRetrans  float64
	ConnPacketLost    float64
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
	totalReports  uint32 // number of times the metric is reported to ringbuffer
}

type connectionSrcDst struct {
	src       [4]uint32
	dst       [4]uint32
	srcPort   uint16
	dstPort   uint16
	direction uint32
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

type connectionMetricLabels struct {
	reporter  string
	startTime string

	sourceWorkload          string
	sourceCanonicalService  string
	sourceCanonicalRevision string
	sourceWorkloadNamespace string
	sourcePrincipal         string
	sourceApp               string
	sourceVersion           string
	sourceCluster           string
	sourceAddress           string

	destinationAddress           string
	destinationPodAddress        string
	destinationPodNamespace      string
	destinationPodName           string
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

func NewConnectionMetricLabel() *connectionMetricLabels {
	return &connectionMetricLabels{}
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

func (c *connectionMetricLabels) withSource(workload *workloadapi.Workload) *connectionMetricLabels {
	if workload == nil {
		return c
	}
	c.sourceWorkload = workload.GetWorkloadName()
	c.sourceCanonicalService = workload.GetCanonicalName()
	c.sourceCanonicalRevision = workload.GetCanonicalRevision()
	c.sourceWorkloadNamespace = workload.GetNamespace()
	c.sourceApp = workload.GetCanonicalName()
	c.sourceVersion = workload.GetCanonicalRevision()
	c.sourceCluster = workload.GetClusterId()
	c.sourcePrincipal = buildPrincipal(workload)
	return c
}

func (c *connectionMetricLabels) withDestination(workload *workloadapi.Workload) *connectionMetricLabels {
	if workload == nil {
		return c
	}
	c.destinationPodNamespace = workload.GetNamespace()
	c.destinationPodName = workload.GetName()
	c.destinationWorkload = workload.GetWorkloadName()
	c.destinationCanonicalService = workload.GetCanonicalName()
	c.destinationCanonicalRevision = workload.GetCanonicalRevision()
	c.destinationWorkloadNamespace = workload.GetNamespace()
	c.destinationApp = workload.GetCanonicalName()
	c.destinationVersion = workload.GetCanonicalRevision()
	c.destinationCluster = workload.GetClusterId()
	c.destinationPrincipal = buildPrincipal(workload)
	return c
}

func (c *connectionMetricLabels) withDestinationService(service *workloadapi.Service) *connectionMetricLabels {
	if service == nil {
		return c
	}
	c.destinationService = service.GetHostname()
	c.destinationServiceName = service.GetName()
	c.destinationServiceNamespace = service.GetNamespace()
	return c
}

func NewMetric(workloadCache cache.WorkloadCache, serviceCache cache.ServiceCache, enableMonitoring bool) *MetricController {
	m := &MetricController{
		workloadCache:         workloadCache,
		serviceCache:          serviceCache,
		workloadMetricCache:   map[workloadMetricLabels]*workloadMetricInfo{},
		serviceMetricCache:    map[serviceMetricLabels]*serviceMetricInfo{},
		connectionMetricCache: map[connectionMetricLabels]*connectionMetricInfo{},
	}
	m.EnableMonitoring.Store(enableMonitoring)
	m.EnableAccesslog.Store(false)
	m.EnableWorkloadMetric.Store(false)
	m.EnableConnectionMetric.Store(false)
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

	tcpConns := make(map[connectionSrcDst]connMetric)

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

			// delta metrics
			var reqMetric requestMetric
			connectType := binary.LittleEndian.Uint32(rec.RawSample)
			originInfo := rec.RawSample[unsafe.Sizeof(connectType):]
			buf := bytes.NewBuffer(originInfo)
			switch connectType {
			case constants.MSG_TYPE_IPV4:
				reqMetric, err = buildV4Metric(buf, tcpConns)
				if err != nil {
					log.Errorf("get connectionV4 info failed: %v", err)
					continue
				}
			case constants.MSG_TYPE_IPV6:
				reqMetric, err = buildV6Metric(buf, tcpConns)
				if err != nil {
					log.Errorf("get connectionV6 info failed: %v", err)
					continue
				}
			default:
				log.Errorf("get connection info failed: %v", err)
				continue
			}

			workloadLabels := workloadMetricLabels{}
			serviceLabels, accesslog := m.buildServiceMetric(&reqMetric)
			if m.EnableWorkloadMetric.Load() {
				workloadLabels = m.buildWorkloadMetric(&reqMetric)
			}

			connectionLabels := connectionMetricLabels{}
			if m.EnableConnectionMetric.Load() && reqMetric.duration > LONG_CONN_METRIC_THRESHOLD {
				connectionLabels = m.buildConnectionMetric(&reqMetric)
			}
			if m.EnableAccesslog.Load() {
				// accesslogs at interval of 5 sec during connection lifecycle if connectionMetrics is enabled and at close of connection
				outputAccesslog(reqMetric, tcpConns[reqMetric.conSrcDstInfo], accesslog)
			}

			m.mutex.Lock()
			if m.EnableWorkloadMetric.Load() {
				m.updateWorkloadMetricCache(reqMetric, workloadLabels, tcpConns[reqMetric.conSrcDstInfo])
			}
			m.updateServiceMetricCache(reqMetric, serviceLabels, tcpConns[reqMetric.conSrcDstInfo])
			if m.EnableConnectionMetric.Load() && reqMetric.duration > LONG_CONN_METRIC_THRESHOLD {
				m.updateConnectionMetricCache(reqMetric, tcpConns[reqMetric.conSrcDstInfo], connectionLabels)
			}
			m.mutex.Unlock()

			if reqMetric.state == TCP_CLOSED {
				delete(tcpConns, reqMetric.conSrcDstInfo)
			}
		}
	}
}

func buildV4Metric(buf *bytes.Buffer, tcpConns map[connectionSrcDst]connMetric) (requestMetric, error) {
	reqMetric := requestMetric{}
	rawStats := connectionDataV4{}

	if err := binary.Read(buf, binary.LittleEndian, &rawStats); err != nil {
		return reqMetric, err
	}

	reqMetric.conSrcDstInfo.src[0] = rawStats.SrcAddr
	reqMetric.conSrcDstInfo.dst[0] = rawStats.DstAddr
	reqMetric.conSrcDstInfo.direction = rawStats.Direction
	reqMetric.direction = rawStats.Direction
	reqMetric.conSrcDstInfo.dstPort = rawStats.DstPort
	reqMetric.conSrcDstInfo.srcPort = rawStats.SrcPort

	// original addr is 0 indicates the connection is
	// workload-type or and not redirected,
	// so we just take from the actual destination
	if rawStats.OriginalAddr == 0 {
		reqMetric.origDstAddr[0] = reqMetric.conSrcDstInfo.dst[0]
		reqMetric.origDstPort = reqMetric.conSrcDstInfo.dstPort
	} else {
		reqMetric.origDstAddr[0] = rawStats.OriginalAddr
		reqMetric.origDstPort = rawStats.OriginalPort
	}

	reqMetric.sentBytes = rawStats.SentBytes - tcpConns[reqMetric.conSrcDstInfo].sentBytes
	reqMetric.receivedBytes = rawStats.ReceivedBytes - tcpConns[reqMetric.conSrcDstInfo].receivedBytes
	reqMetric.state = rawStats.State
	reqMetric.success = rawStats.ConnectSuccess
	reqMetric.duration = rawStats.Duration
	reqMetric.startTime = rawStats.StartTime
	reqMetric.lastReportTime = rawStats.LastReportTime
	reqMetric.srtt = rawStats.statistics.SRttTime
	reqMetric.minRtt = rawStats.statistics.RttMin
	reqMetric.totalRetrans = rawStats.statistics.Retransmits - tcpConns[reqMetric.conSrcDstInfo].totalRetrans
	reqMetric.packetLost = rawStats.statistics.LostPackets - tcpConns[reqMetric.conSrcDstInfo].packetLost

	cm, ok := tcpConns[reqMetric.conSrcDstInfo]
	if ok {
		cm.receivedBytes = rawStats.ReceivedBytes
		cm.sentBytes = rawStats.SentBytes
		cm.totalRetrans = rawStats.statistics.Retransmits
		cm.packetLost = rawStats.statistics.LostPackets
		cm.totalReports++
		tcpConns[reqMetric.conSrcDstInfo] = cm
	} else {
		tcpConns[reqMetric.conSrcDstInfo] = connMetric{
			receivedBytes: rawStats.ReceivedBytes,
			sentBytes:     rawStats.SentBytes,
			totalRetrans:  rawStats.statistics.Retransmits,
			packetLost:    rawStats.statistics.LostPackets,
			totalReports:  1,
		}
	}

	return reqMetric, nil
}

func buildV6Metric(buf *bytes.Buffer, tcpConns map[connectionSrcDst]connMetric) (requestMetric, error) {
	reqMetric := requestMetric{}
	rawStats := connectionDataV6{}
	if err := binary.Read(buf, binary.LittleEndian, &rawStats); err != nil {
		return reqMetric, err
	}
	reqMetric.conSrcDstInfo.src = rawStats.SrcAddr
	reqMetric.conSrcDstInfo.dst = rawStats.DstAddr
	reqMetric.conSrcDstInfo.direction = rawStats.Direction
	reqMetric.direction = rawStats.Direction
	reqMetric.conSrcDstInfo.dstPort = rawStats.DstPort
	reqMetric.conSrcDstInfo.srcPort = rawStats.SrcPort

	// original addr is 0 indicates the connection is
	// workload-type or and not redirected,
	// so we just take from the actual destination
	if !isOrigDstSet(rawStats.OriginalAddr) {
		reqMetric.origDstAddr = reqMetric.conSrcDstInfo.dst
		reqMetric.origDstPort = reqMetric.conSrcDstInfo.dstPort
	} else {
		reqMetric.origDstAddr = rawStats.OriginalAddr
		reqMetric.origDstPort = rawStats.OriginalPort
	}

	reqMetric.sentBytes = rawStats.SentBytes - tcpConns[reqMetric.conSrcDstInfo].sentBytes
	reqMetric.receivedBytes = rawStats.ReceivedBytes - tcpConns[reqMetric.conSrcDstInfo].receivedBytes
	reqMetric.state = rawStats.State
	reqMetric.success = rawStats.ConnectSuccess
	reqMetric.duration = rawStats.Duration
	reqMetric.startTime = rawStats.StartTime
	reqMetric.lastReportTime = rawStats.LastReportTime
	reqMetric.srtt = rawStats.statistics.SRttTime
	reqMetric.minRtt = rawStats.statistics.RttMin
	reqMetric.totalRetrans = rawStats.statistics.Retransmits - tcpConns[reqMetric.conSrcDstInfo].totalRetrans
	reqMetric.packetLost = rawStats.statistics.LostPackets - tcpConns[reqMetric.conSrcDstInfo].packetLost

	cm, ok := tcpConns[reqMetric.conSrcDstInfo]
	if ok {
		cm.receivedBytes = rawStats.ReceivedBytes
		cm.sentBytes = rawStats.SentBytes
		cm.totalRetrans = rawStats.statistics.Retransmits
		cm.packetLost = rawStats.statistics.LostPackets
		cm.totalReports++
		tcpConns[reqMetric.conSrcDstInfo] = cm
	} else {
		tcpConns[reqMetric.conSrcDstInfo] = connMetric{
			receivedBytes: rawStats.ReceivedBytes,
			sentBytes:     rawStats.SentBytes,
			totalRetrans:  rawStats.statistics.Retransmits,
			packetLost:    rawStats.statistics.LostPackets,
			totalReports:  1,
		}
	}

	return reqMetric, nil
}

func (m *MetricController) buildWorkloadMetric(reqMetric *requestMetric) workloadMetricLabels {
	var dstAddr, srcAddr []byte
	for i := range reqMetric.conSrcDstInfo.dst {
		dstAddr = binary.LittleEndian.AppendUint32(dstAddr, reqMetric.conSrcDstInfo.dst[i])
		srcAddr = binary.LittleEndian.AppendUint32(srcAddr, reqMetric.conSrcDstInfo.src[i])
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

	switch reqMetric.direction {
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

func (m *MetricController) buildServiceMetric(reqMetric *requestMetric) (serviceMetricLabels, logInfo) {
	var dstAddr, srcAddr, origAddr []byte
	for i := range reqMetric.conSrcDstInfo.dst {
		dstAddr = binary.LittleEndian.AppendUint32(dstAddr, reqMetric.conSrcDstInfo.dst[i])
		srcAddr = binary.LittleEndian.AppendUint32(srcAddr, reqMetric.conSrcDstInfo.src[i])
		origAddr = binary.LittleEndian.AppendUint32(origAddr, reqMetric.origDstAddr[i])
	}

	dstWorkload, dstIp := m.getWorkloadByAddress(restoreIPv4(dstAddr))
	srcWorkload, srcIp := m.getWorkloadByAddress(restoreIPv4(srcAddr))

	dstService := m.fetchOriginalService(restoreIPv4(origAddr), uint32(reqMetric.origDstPort))
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
	accesslog.destinationAddress = dstIp + ":" + fmt.Sprintf("%d", reqMetric.conSrcDstInfo.dstPort)
	accesslog.sourceAddress = srcIp + ":" + fmt.Sprintf("%d", reqMetric.conSrcDstInfo.srcPort)

	switch reqMetric.direction {
	case constants.INBOUND:
		trafficLabels.reporter = "destination"
		accesslog.direction = "INBOUND"
	case constants.OUTBOUND:
		trafficLabels.reporter = "source"
		accesslog.direction = "OUTBOUND"
	}

	accesslog.state = TCP_STATES[reqMetric.state]
	return *trafficLabels, *accesslog
}

func (m *MetricController) buildConnectionMetric(reqMetric *requestMetric) connectionMetricLabels {
	var dstAddr, srcAddr, origAddr []byte
	for i := range reqMetric.conSrcDstInfo.dst {
		dstAddr = binary.LittleEndian.AppendUint32(dstAddr, reqMetric.conSrcDstInfo.dst[i])
		srcAddr = binary.LittleEndian.AppendUint32(srcAddr, reqMetric.conSrcDstInfo.src[i])
		origAddr = binary.LittleEndian.AppendUint32(origAddr, reqMetric.origDstAddr[i])
	}

	dstWorkload, dstIP := m.getWorkloadByAddress(restoreIPv4(dstAddr))
	srcWorkload, srcIP := m.getWorkloadByAddress(restoreIPv4(srcAddr))

	if srcWorkload == nil {
		return connectionMetricLabels{}
	}

	dstService := m.fetchOriginalService(restoreIPv4(origAddr), uint32(reqMetric.origDstPort))
	// if dstService not found, we use the address as hostname for metrics
	if dstService == nil {
		dstService = &workloadapi.Service{
			Hostname: dstIP,
		}
	}

	trafficLabels := NewConnectionMetricLabel()
	trafficLabels.withSource(srcWorkload).withDestination(dstWorkload).withDestinationService(dstService)

	trafficLabels.destinationAddress = dstIP + ":" + fmt.Sprintf("%d", reqMetric.conSrcDstInfo.dstPort)
	trafficLabels.sourceAddress = srcIP + ":" + fmt.Sprintf("%d", reqMetric.conSrcDstInfo.srcPort)
	trafficLabels.destinationPodAddress = dstIP
	trafficLabels.requestProtocol = "tcp"
	trafficLabels.connectionSecurityPolicy = "mutual_tls"

	switch reqMetric.direction {
	case constants.INBOUND:
		trafficLabels.reporter = "destination"
	case constants.OUTBOUND:
		trafficLabels.reporter = "source"
	}

	startTime := calculateUptime(osStartTime, reqMetric.startTime)
	startTimeInfo := fmt.Sprintf("%v", startTime)
	trafficLabels.startTime = startTimeInfo

	return *trafficLabels
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

func (m *MetricController) updateWorkloadMetricCache(reqMetric requestMetric, labels workloadMetricLabels, metric connMetric) {
	v, ok := m.workloadMetricCache[labels]
	if ok {
		if reqMetric.state == TCP_ESTABLISHED && metric.totalReports == 1 {
			v.WorkloadConnOpened = v.WorkloadConnOpened + 1
		}
		if reqMetric.state == TCP_CLOSED {
			v.WorkloadConnClosed = v.WorkloadConnClosed + 1
		}
		if reqMetric.success != connection_success {
			v.WorkloadConnFailed = v.WorkloadConnFailed + 1
		}
		v.WorkloadConnReceivedBytes = v.WorkloadConnReceivedBytes + float64(reqMetric.receivedBytes)
		v.WorkloadConnSentBytes = v.WorkloadConnSentBytes + float64(reqMetric.sentBytes)
		v.WorkloadConnTotalRetrans = v.WorkloadConnTotalRetrans + float64(reqMetric.totalRetrans)
		v.WorkloadConnPacketLost = v.WorkloadConnPacketLost + float64(reqMetric.packetLost)
	} else {
		newWorkloadMetricInfo := workloadMetricInfo{}
		if reqMetric.state == TCP_ESTABLISHED && metric.totalReports == 1 {
			newWorkloadMetricInfo.WorkloadConnOpened = 1
		}
		if reqMetric.state == TCP_CLOSED {
			newWorkloadMetricInfo.WorkloadConnClosed = 1
		}
		if reqMetric.success != connection_success {
			newWorkloadMetricInfo.WorkloadConnFailed = 1
		}
		newWorkloadMetricInfo.WorkloadConnReceivedBytes = float64(reqMetric.receivedBytes)
		newWorkloadMetricInfo.WorkloadConnSentBytes = float64(reqMetric.sentBytes)
		newWorkloadMetricInfo.WorkloadConnTotalRetrans = float64(reqMetric.totalRetrans)
		newWorkloadMetricInfo.WorkloadConnPacketLost = float64(reqMetric.packetLost)
		m.workloadMetricCache[labels] = &newWorkloadMetricInfo
	}
}

func (m *MetricController) updateServiceMetricCache(reqMetric requestMetric, labels serviceMetricLabels, metric connMetric) {
	v, ok := m.serviceMetricCache[labels]
	if ok {
		if reqMetric.state == TCP_ESTABLISHED && metric.totalReports == 1 {
			v.ServiceConnOpened = v.ServiceConnOpened + 1
		}
		if reqMetric.state == TCP_CLOSED {
			v.ServiceConnClosed = v.ServiceConnClosed + 1
		}
		if reqMetric.success != connection_success {
			v.ServiceConnFailed = v.ServiceConnFailed + 1
		}
		v.ServiceConnReceivedBytes = v.ServiceConnReceivedBytes + float64(reqMetric.receivedBytes)
		v.ServiceConnSentBytes = v.ServiceConnSentBytes + float64(reqMetric.sentBytes)
	} else {
		newServiceMetricInfo := serviceMetricInfo{}
		if reqMetric.state == TCP_ESTABLISHED && metric.totalReports == 1 {
			newServiceMetricInfo.ServiceConnOpened = 1
		}
		if reqMetric.state == TCP_CLOSED {
			newServiceMetricInfo.ServiceConnClosed = 1
		}
		if reqMetric.success != connection_success {
			newServiceMetricInfo.ServiceConnFailed = 1
		}
		newServiceMetricInfo.ServiceConnReceivedBytes = float64(reqMetric.receivedBytes)
		newServiceMetricInfo.ServiceConnSentBytes = float64(reqMetric.sentBytes)
		m.serviceMetricCache[labels] = &newServiceMetricInfo
	}
}

func (m *MetricController) updateConnectionMetricCache(reqMetric requestMetric, connMetric connMetric, labels connectionMetricLabels) {
	v, ok := m.connectionMetricCache[labels]
	if ok {
		v.ConnSentBytes = v.ConnSentBytes + float64(reqMetric.sentBytes)
		v.ConnReceivedBytes = v.ConnReceivedBytes + float64(reqMetric.receivedBytes)
		v.ConnPacketLost = v.ConnPacketLost + float64(reqMetric.packetLost)
		v.ConnTotalRetrans = v.ConnTotalRetrans + float64(reqMetric.totalRetrans)
	} else {
		newConnectionMetricInfo := connectionMetricInfo{}
		newConnectionMetricInfo.ConnSentBytes = float64(connMetric.sentBytes)
		newConnectionMetricInfo.ConnReceivedBytes = float64(connMetric.receivedBytes)
		newConnectionMetricInfo.ConnPacketLost = float64(connMetric.packetLost)
		newConnectionMetricInfo.ConnTotalRetrans = float64(connMetric.totalRetrans)
		m.connectionMetricCache[labels] = &newConnectionMetricInfo
	}
	if reqMetric.state == TCP_CLOSED {
		deleteLock.Lock()
		deleteConnection = append(deleteConnection, &labels)
		deleteLock.Unlock()
	}
}

func (m *MetricController) updatePrometheusMetric() {
	m.mutex.Lock()
	workloadInfoCache := m.workloadMetricCache
	serviceInfoCache := m.serviceMetricCache
	connectionInfoCache := m.connectionMetricCache
	m.workloadMetricCache = map[workloadMetricLabels]*workloadMetricInfo{}
	m.serviceMetricCache = map[serviceMetricLabels]*serviceMetricInfo{}
	m.connectionMetricCache = map[connectionMetricLabels]*connectionMetricInfo{}
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

	for k, v := range connectionInfoCache {
		connectionLabels := struct2map(k)
		tcpConnectionTotalSendBytes.With(connectionLabels).Add(v.ConnSentBytes)
		tcpConnectionTotalReceivedBytes.With(connectionLabels).Add(v.ConnReceivedBytes)
		tcpConnectionTotalPacketLost.With(connectionLabels).Add(v.ConnPacketLost)
		tcpConnectionTotalRetrans.With(connectionLabels).Add(v.ConnTotalRetrans)
	}

	// delete metrics
	deleteLock.Lock()
	// Creating a copy reduces the amount of time spent adding locks in the programme
	workloadReplica := deleteWorkload
	deleteWorkload = nil
	serviceReplica := deleteService
	deleteService = nil
	connReplica := deleteConnection
	deleteConnection = []*connectionMetricLabels{}
	deleteLock.Unlock()

	for i := 0; i < len(workloadReplica); i++ {
		deleteWorkloadMetricInPrometheus(workloadReplica[i])
	}
	for i := 0; i < len(serviceReplica); i++ {
		deleteServiceMetricInPrometheus(serviceReplica[i])
	}
	for i := 0; i < len(connReplica); i++ {
		deleteConnectionMetricInPrometheus(connReplica[i])
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
