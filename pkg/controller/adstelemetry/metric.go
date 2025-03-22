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

package adstelemetry

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/ads/cache"
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

type MetricController struct {
	EnableAccesslog      atomic.Bool
	EnableMonitoring     atomic.Bool
	EnableWorkloadMetric atomic.Bool
	adsMetricCache       map[adsMetricLabels]*adsMetricInfo
	NameByAddr           map[string]string
	mutex                sync.RWMutex
}
type adsMetricInfo struct {
	SocketConnOpened        float64
	SocketConnClosed        float64
	SocketConnSentBytes     float64
	SocketConnReceivedBytes float64
	SocketConnFailed        float64
}
type statistics struct {
	SentBytes      uint32
	ReceivedBytes  uint32
	ConnectSuccess uint32
	Direction      uint32
	State          uint32
	Duration       uint64
	CloseTime      uint64
	// TODO: statistics below are not used for now
	Protocol     uint32
	SRttTime     uint32
	RttMin       uint32
	Retransmits  uint32
	LostPackets  uint32
	Dst_svc_name [192]byte
}

// connectionDataV4 read from ebpf ringbuf and padding with `_`
type connectionDataV4 struct {
	SrcAddr      uint32
	DstAddr      uint32
	SrcPort      uint16
	DstPort      uint16
	_            [6]uint32
	OriginalAddr uint32
	OriginalPort uint16
	_            uint16
	_            [3]uint32
	statistics
}

type requestMetric struct {
	src           [4]uint32
	dst           [4]uint32
	srcPort       uint16
	dstPort       uint16
	origDstAddr   [4]uint32
	origDstPort   uint16
	direction     uint32
	receivedBytes uint32
	sentBytes     uint32
	state         uint32
	success       uint32
	duration      uint64
	closeTime     uint64
	srtt          uint32
	minRtt        uint32
	totalRetrans  uint32
	PacketLost    uint32
	Dst_svc_name  [192]byte
}
type adsMetricLabels struct {
	reporter string

	sourcePodAddress      string
	sourcePodPort         string
	sourcePodName         string
	destinationPodAddress string
	destinationPodPort    string
	destinationSvcName    string
}

func NewAdsMetricLabel() *adsMetricLabels {
	return &adsMetricLabels{}
}

func (w *adsMetricLabels) withSource(adsconfig *cache.Adsconfig) *adsMetricLabels {
	if adsconfig == nil {
		return w
	}

	w.sourcePodAddress = adsconfig.GetAdsconfigAddress()
	w.sourcePodPort = adsconfig.GetAdsconfigPort()
	w.sourcePodName = adsconfig.GetAdsconfigName()
	return w
}

func (w *adsMetricLabels) withDestination(adsconfig *cache.Adsconfig) *adsMetricLabels {
	if adsconfig == nil {
		return w
	}

	w.destinationPodPort = adsconfig.GetAdsconfigPort()
	w.destinationPodAddress = adsconfig.GetAdsconfigAddress()
	w.destinationSvcName = adsconfig.GetAdsconfigSvcName()

	return w
}

func NewMetric(AdsCache *cache.AdsCache, enableMonitoring bool, managerCache map[string]string) *MetricController {
	m := &MetricController{
		adsMetricCache: map[adsMetricLabels]*adsMetricInfo{},
		NameByAddr:     managerCache,
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
	log.Printf("MetricController RUN")
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
			log.Printf("MetricController LOAD")
			if !m.EnableMonitoring.Load() {
				continue
			}
			log.Printf("MetricController ENABLED")
			data := requestMetric{}
			rec := ringbuf.Record{}
			if err := reader.ReadInto(&rec); err != nil {
				log.Errorf("ringbuf reader FAILED to read, err: %v", err)
				continue
			}
			if len(rec.RawSample) != int(unsafe.Sizeof(connectionDataV4{})) {
				log.Errorf("wrong length %v of a msg, should be %v", len(rec.RawSample), int(unsafe.Sizeof(connectionDataV4{})))
				continue
			}
			connectType := binary.LittleEndian.Uint32(rec.RawSample)
			originInfo := rec.RawSample[unsafe.Sizeof(connectType):]
			buf := bytes.NewBuffer(originInfo)
			switch connectType {
			case constants.MSG_TYPE_IPV4:
				data, err = buildV4Metric(buf)
			default:
				log.Errorf("get connection info failed: %v", err)
				continue
			}
			log.Printf("data: %v", data)
			// serviceLabels, accesslog := m.buildServiceMetric(&data)
			// OutputAccesslog(data, accesslog)
			adsLabels := m.buildAdsMetric(&data)

			m.mutex.Lock()
			m.updateAdsMetricCache(data, adsLabels)
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

	// original addr is 0 indicates the connection is
	// workload-type or and not redirected,
	// so we just take from the actual destination
	if connectData.OriginalAddr == 0 {
		data.origDstAddr[0] = data.dst[0]
		data.origDstPort = data.dstPort
	} else {
		data.origDstAddr[0] = connectData.OriginalAddr
		data.origDstPort = connectData.OriginalPort
	}

	data.sentBytes = connectData.SentBytes
	data.receivedBytes = connectData.ReceivedBytes
	data.state = connectData.State
	data.success = connectData.ConnectSuccess
	data.duration = connectData.Duration
	data.closeTime = connectData.CloseTime
	data.srtt = connectData.statistics.SRttTime
	data.minRtt = connectData.statistics.RttMin
	data.totalRetrans = connectData.statistics.Retransmits
	data.PacketLost = connectData.statistics.LostPackets
	data.Dst_svc_name = connectData.statistics.Dst_svc_name

	return data, nil
}

func NewAdsDstConfig(addr []byte, port uint16, name string) *cache.Adsconfig {
	address := net.IPv4(addr[0], addr[1], addr[2], addr[3]).String()
	//portstring := strconv.FormatUint(uint64(binary.BigEndian.Uint16([]byte{byte(port), byte(port >> 8)})), 10)

	return &cache.Adsconfig{
		Address: address,
		Port:    DEFAULT_UNKNOWN,
		Name:    name,
	}
}

func NewAdsSrcConfig(addr []byte, port uint16, manageCache map[string]string) *cache.Adsconfig {
	address := net.IPv4(addr[0], addr[1], addr[2], addr[3]).String()
	//portstring := strconv.FormatUint(uint64(binary.BigEndian.Uint16([]byte{byte(port), byte(port >> 8)})), 10)
	name := manageCache[address]
	if name == "" {
		name = DEFAULT_UNKNOWN
	}
	return &cache.Adsconfig{
		Address: address,
		Port:    DEFAULT_UNKNOWN,
		Name:    name,
	}
}

func byteArrayToString(b [192]byte) string {
	// 查找第一个结束符的位置
	end := bytes.IndexByte(b[:], 0x00)
	if end == -1 {
		end = len(b) // 若无结束符，则转换整个数组
	}
	// 转换为字符串（自动处理内存复制）
	return string(b[:end])
}

func (m *MetricController) buildAdsMetric(data *requestMetric) adsMetricLabels {
	var dstAddr, srcAddr []byte
	for i := range data.dst {
		dstAddr = binary.LittleEndian.AppendUint32(dstAddr, data.dst[i])
		srcAddr = binary.LittleEndian.AppendUint32(srcAddr, data.src[i])
	}
	dstAdsConfig := NewAdsDstConfig(restoreIPv4(dstAddr), data.dstPort, byteArrayToString(data.Dst_svc_name))
	srcAdsConfig := NewAdsSrcConfig(restoreIPv4(srcAddr), data.srcPort, m.NameByAddr)

	trafficLabels := NewAdsMetricLabel()
	trafficLabels.withSource(srcAdsConfig).withDestination(dstAdsConfig)

	switch data.direction {
	case constants.INBOUND:
		trafficLabels.reporter = "destination"
	case constants.OUTBOUND:
		trafficLabels.reporter = "source"
	}

	return *trafficLabels
}

func (m *MetricController) updateAdsMetricCache(data requestMetric, labels adsMetricLabels) {
	v, ok := m.adsMetricCache[labels]
	if ok {
		if data.state == TCP_ESTABLISHED {
			v.SocketConnOpened = v.SocketConnOpened + 1
		}
		if data.state == TCP_CLOSTED {
			v.SocketConnClosed = v.SocketConnClosed + 1
		}
		if data.success != connection_success {
			v.SocketConnFailed = v.SocketConnFailed + 1
		}
		v.SocketConnReceivedBytes = v.SocketConnReceivedBytes + float64(data.receivedBytes)
		v.SocketConnSentBytes = v.SocketConnSentBytes + float64(data.sentBytes)
	} else {
		newAdsMetricInfo := adsMetricInfo{}
		if data.state == TCP_ESTABLISHED {
			newAdsMetricInfo.SocketConnOpened = 1
		}
		if data.state == TCP_CLOSTED {
			newAdsMetricInfo.SocketConnClosed = 1
		}
		if data.success != connection_success {
			newAdsMetricInfo.SocketConnFailed = 1
		}
		newAdsMetricInfo.SocketConnReceivedBytes = float64(data.receivedBytes)
		newAdsMetricInfo.SocketConnSentBytes = float64(data.sentBytes)
		m.adsMetricCache[labels] = &newAdsMetricInfo
	}
}

func (m *MetricController) updatePrometheusMetric() {
	m.mutex.Lock()
	adsInfoCache := m.adsMetricCache
	m.adsMetricCache = map[adsMetricLabels]*adsMetricInfo{}
	m.mutex.Unlock()

	log.Infof("update prometheus metric")
	for k, v := range adsInfoCache {
		adsLabels := struct2map(k)
		log.Infof("adsLabels: %v", adsLabels)
		tcpConnectionOpenedInAds.With(adsLabels).Add(v.SocketConnOpened)
		tcpConnectionClosedInAds.With(adsLabels).Add(v.SocketConnClosed)
		tcpConnectionFailedInAds.With(adsLabels).Add(v.SocketConnFailed)
		tcpReceivedBytesInAds.With(adsLabels).Add(v.SocketConnReceivedBytes)
		tcpSentBytesInAds.With(adsLabels).Add(v.SocketConnSentBytes)
	}

	// delete metrics
	deleteLock.Lock()
	// Creating a copy reduces the amount of time spent adding locks in the programme
	adsReplica := deleteAds
	deleteAds = nil
	deleteLock.Unlock()

	for i := 0; i < len(adsReplica); i++ {
		deleteAdsMetricInPrometheus(adsReplica[i])
	}
}

func struct2map(labels interface{}) map[string]string {
	if reflect.TypeOf(labels).Kind() == reflect.Struct {
		trafficLabelsMap := make(map[string]string)
		val := reflect.ValueOf(labels)
		num := val.NumField()
		fmt.Printf("fieldInfo: %v\n", num)
		for i := 0; i < num; i++ {
			fieldInfo := val.Type().Field(i)
			fmt.Printf("fieldInfo: %v\n", fieldInfo.Name)
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
