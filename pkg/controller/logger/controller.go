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
package logger

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/utils"
)

const SERVICE_ID = "[SERVICE_ID]"
const BACKEND_UID = "[BACKEND_UID]"

type BpfLogController struct {
	logMap *ebpf.Map
	hash   *utils.HashName
}

var log = logger.NewLoggerScope("ebpf")

// TODO: move to a separate controller pkg
// print bpf log in kmesh-daemon
func NewBpfLogController(logMap *ebpf.Map) *BpfLogController {
	return &BpfLogController{logMap: logMap, hash: utils.NewHashName()}
}

func (c *BpfLogController) Run(stopCh <-chan struct{}) {
	c.handleLogEvents(stopCh)
}

func (c *BpfLogController) handleLogEvents(stopCh <-chan struct{}) {
	reader, err := ringbuf.NewReader(c.logMap)
	if err != nil {
		log.Errorf("create rb reader failed: %v", err)
		return
	}

	for {
		select {
		case <-stopCh:
			return
		default:
			record, err := reader.Read()
			if err != nil {
				log.Errorf("ebpf log read failed: %v", err)
				continue
			}
			if msg, err := c.decodeEbpfLog(record.RawSample); err != nil {
				log.Errorf("ebpf log decode failed: %v", err)
			} else {
				log.Info(msg)
			}
		}
	}
}

// 4 is the msg length, -1 is the '\0' terminate character
func (c *BpfLogController) decodeEbpfLog(data []byte) (string, error) {
	lenOfMsg := binary.NativeEndian.Uint32(data[0:4])
	if len(data) < int(lenOfMsg+4) {
		return "", fmt.Errorf("invalid bpf log message")
	}

	msg := string(data[4 : 4+lenOfMsg])
	if data[4+lenOfMsg-1] == '\x00' {
		msg = msg[:len(msg)-1]
	}
	msg = strings.TrimSuffix(msg, "\n")

	return c.renderLogMsg(msg), nil
}

// replace the sub str after pattern with the hash value
func (c *BpfLogController) renderLogMsg(msg string) string {
	for _, pattern := range []string{SERVICE_ID, BACKEND_UID} {
		if index := strings.Index(msg, pattern); index != -1 {
			first := msg[:index]
			second := msg[index:]
			sections := strings.SplitN(second, " ", 3)
			if len(sections) == 3 {
				num, err := strconv.ParseUint(sections[1], 10, 64)
				if err == nil {
					if str := c.hash.NumToStr(uint32(num)); str != "" {
						return first + pattern + " " + str + " " + strings.TrimSuffix(sections[2], "\n")
					}
				}
			}
			continue
		}
	}

	return msg
}
