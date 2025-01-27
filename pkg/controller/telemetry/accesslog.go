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
	"fmt"
	"syscall"
	"time"

	"kmesh.net/kmesh/api/v2/workloadapi"
)

type logInfo struct {
	direction       string
	sourceAddress   string
	sourceWorkload  string
	sourceNamespace string

	destinationAddress   string
	destinationService   string
	destinationWorkload  string
	destinationNamespace string
}

func NewLogInfo() *logInfo {
	return &logInfo{
		direction:            DEFAULT_UNKNOWN,
		sourceAddress:        DEFAULT_UNKNOWN,
		sourceWorkload:       DEFAULT_UNKNOWN,
		sourceNamespace:      DEFAULT_UNKNOWN,
		destinationAddress:   DEFAULT_UNKNOWN,
		destinationService:   DEFAULT_UNKNOWN,
		destinationWorkload:  DEFAULT_UNKNOWN,
		destinationNamespace: DEFAULT_UNKNOWN,
	}
}

func (l *logInfo) withSource(workload *workloadapi.Workload) *logInfo {
	if workload.GetNamespace() != "" {
		l.sourceNamespace = workload.GetNamespace()
	}
	if workload.GetName() != "" {
		l.sourceWorkload = workload.GetName()
	}
	return l
}

func (l *logInfo) withDestination(workload *workloadapi.Workload) *logInfo {
	if workload.GetName() != "" {
		l.destinationWorkload = workload.GetName()
	}
	return l
}

func (l *logInfo) withDestinationService(service *workloadapi.Service) *logInfo {
	if service.GetNamespace() != "" {
		l.destinationNamespace = service.GetNamespace()
	}
	if service.GetHostname() != "" {
		l.destinationService = service.GetHostname()
	}
	return l
}

func OutputAccesslog(data requestMetric, accesslog logInfo) {
	logStr := buildAccesslog(data, accesslog)
	fmt.Println("accesslog:", logStr)
}

func buildAccesslog(data requestMetric, accesslog logInfo) string {
	closeTime := data.closeTime
	uptime := calculateUptime(osStartTime, closeTime)

	timeInfo := fmt.Sprintf("%v", uptime)
	sourceInfo := fmt.Sprintf("src.addr=%s, src.workload=%s, src.namespace=%s", accesslog.sourceAddress, accesslog.sourceWorkload, accesslog.sourceNamespace)
	destinationInfo := fmt.Sprintf("dst.addr=%s, dst.service=%s, dst.workload=%s, dst.namespace=%s", accesslog.destinationAddress, accesslog.destinationService, accesslog.destinationWorkload, accesslog.destinationNamespace)
	connectionInfo := fmt.Sprintf("direction=%s, sent_bytes=%d, received_bytes=%d, srtt=%dus, min_rtt=%dus, duration=%vms", accesslog.direction, data.sentBytes, data.receivedBytes, data.srtt, data.minRtt, (float64(data.duration) / 1000000.0))

	logResult := fmt.Sprintf("%s %s, %s, %s", timeInfo, sourceInfo, destinationInfo, connectionInfo)
	return logResult
}

func getOSBootTime() (time.Time, error) {
	now := time.Now()
	now = now.Round(time.Duration(now.Second()))

	sysinfo := &syscall.Sysinfo_t{}
	if err := syscall.Sysinfo(sysinfo); err != nil {
		return time.Time{}, err
	}

	uptime := time.Duration(sysinfo.Uptime) * time.Second
	lastRebootTime := now.Add(-uptime)

	return lastRebootTime, nil
}

func calculateUptime(startTime time.Time, elapsedTimeNs uint64) time.Time {
	elapsedDuration := time.Duration(elapsedTimeNs) * time.Nanosecond
	currentTime := startTime.Add(elapsedDuration)
	return currentTime
}
