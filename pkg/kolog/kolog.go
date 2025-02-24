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
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, err
	}

	for _, line := range strings.Split(string(data), "\n") {
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
		log.Printf("[%s] %s\n", eventTime.Format(time.DateTime), line)
	}
}

func KmeshModuleLog(stopCh <-chan struct{}) {
	go func() {
		bootTime, err := getBootTime()
		if err != nil {
			log.Fatalf("getBootTime: %v", err)
		}
		startTimestamp := uint64(time.Now().UnixMicro() - bootTime.UnixMicro())

		file, err := os.Open("/dev/kmsg")
		if err != nil {
			log.Fatalf("open /dev/kmsg failed: %v", err)
		}
		defer file.Close()

		reader := bufio.NewReader(file)
		for {
			select {
			case <-stopCh:
				return
			default:
				line, err := reader.ReadString('\n')
				if err != nil {
					if err.Error() == "EOF" {
						time.Sleep(100 * time.Millisecond)
						continue
					}
					log.Fatalf("ReadString err: %v", err)
				}
				parseKmsgLine(line, bootTime, startTimestamp)
			}
		}
	}()
}
