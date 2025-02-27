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

package kolog

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"kmesh.net/kmesh/pkg/logger"
)

var (
	log = logger.NewLoggerScope("Kmesh_module")
)

// Used for timestamp conversion
func getBootTime() (time.Time, error) {
	data, err := os.Open("/proc/stat")
	if err != nil {
		return time.Time{}, err
	}
	scanner := bufio.NewScanner(data)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "btime ") {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}
			btime, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return time.Time{}, err
			}
			return time.Unix(btime, 0), nil
		}
	}
	return time.Time{}, fmt.Errorf("btime not found")
}

// Convert to a readable time:dataTime
func timeParse(timestamp uint64, bootTime time.Time) time.Time {
	totalNano := (timestamp) * uint64(time.Microsecond)
	return bootTime.Add(time.Duration(totalNano))
}

func parseKmsgLine(line string, bootTime time.Time, appStartTimestamp uint64) {
	parts := strings.Split(line, ",")
	if len(parts) < 3 {
		return
	}

	// parse timestamp
	timestampStr := strings.TrimSpace(parts[2])
	timestamp, err := strconv.ParseUint(timestampStr, 10, 64)
	if err != nil {
		log.Printf("Parse timestamp error: %v", err)
		return
	}

	if timestamp < appStartTimestamp {
		return
	}
	eventTime := timeParse(timestamp, bootTime)

	// parse is Kmesh log
	if strings.Contains(line, "Kmesh_module") {
		// The log print will add a '\n' at the end again,
		// so the original string's '\n' needs to be removed.
		line = strings.TrimSuffix(line, "\n")
		log.Printf("[%s] %s", eventTime.Format(time.DateTime), line)
	}
}

func KmeshModuleLog(stopCh <-chan struct{}) {
	go func() {
		bootTime, err := getBootTime()
		if err != nil {
			log.Errorf("getBootTime: %v, ko log time is inaccurate", err)
		}
		startTimestamp := uint64(time.Now().UnixMicro() - bootTime.UnixMicro())

		file, err := os.Open("/dev/kmsg")
		if err != nil {
			log.Errorf("open /dev/kmsg failed: %v, Failed to read ko log", err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for {
			select {
			case <-stopCh:
				return
			default:
				if scanner.Scan() {
					line := scanner.Text()
					parseKmsgLine(line, bootTime, startTimestamp)
				}
			}
		}
	}()
}
