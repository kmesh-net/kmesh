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
	"bufio"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type logInfo struct {
	direction     string
	sentBytes     uint32
	receivedBytes uint32
	duration      uint64

	sourceAddress   string
	sourceWorkload  string
	sourceNamespace string

	destinationAddress   string
	destinationService   string
	destinationWorkload  string
	destinationNamespace string
}

func RunAccesslog(data requestMetric, accesslog logInfo) {
	_ = buildAccesslog(data, accesslog)
}

func buildAccesslog(data requestMetric, accesslog logInfo) string {
	closeTime := data.closeTime
	startTime := getOSBootTime()
	uptime := calculateUptime(startTime, closeTime)

	timeInfo := fmt.Sprintf("%v", uptime)
	sourceInfo := fmt.Sprintf("src.addr=%s, src.workload=%s, src.namespace=%s", accesslog.sourceAddress, accesslog.sourceWorkload, accesslog.sourceNamespace)
	destinationInfo := fmt.Sprintf("dst.addr=%s, dst.service=%s, dst.workload=%s, dst.namespace=%s", accesslog.destinationAddress, accesslog.destinationService, accesslog.destinationWorkload, accesslog.destinationNamespace)
	connectionInfo := fmt.Sprintf("direction=%s, sent_bytes=%d, received_bytes=%d, duration=%vms", accesslog.direction, data.sentBytes, data.receivedBytes, (float64(data.duration) / 1000000.0))

	logResult := fmt.Sprintf("%s %s, %s, %s", timeInfo, sourceInfo, destinationInfo, connectionInfo)
	log.Infof("%s", logResult)
	return logResult
}

func getOSBootTime() time.Time {
	cmd := exec.Command("uptime", "-s")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println(err)
	}
	cmd.Start()
	reader := bufio.NewReader(stdout)
	timeStr, err2 := reader.ReadString('\n')
	if err2 != nil {
		log.Errorf("get system last start time error: %v", err2)
	}
	timeStr = strings.Trim(timeStr, "\n")
	bootTime, err := time.Parse("2006-01-02 15:04:05", timeStr)
	return bootTime
}

func calculateUptime(startTime time.Time, elapsedTimeNs uint64) time.Time {
	elapsedDuration := time.Duration(elapsedTimeNs) * time.Nanosecond
	currentTime := startTime.Add(elapsedDuration)
	return currentTime
}
