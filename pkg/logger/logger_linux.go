//go:build linux

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
	"context"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// print bpf log in kmesh-daemon
func StartLogReader(ctx context.Context, logMapFd *ebpf.Map) {
	go handleLogEvents(ctx, logMapFd)
}

func handleLogEvents(ctx context.Context, rbMap *ebpf.Map) {
	log := NewLoggerScope("ebpf")
	events, err := ringbuf.NewReader(rbMap)
	if err != nil {
		log.Errorf("ringbuf new reader from rb map failed:%v", err)
		return
	}
	defer events.Close()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			record, err := events.Read()
			if err != nil {
				return
			}
			le, err := decodeRecord(record.RawSample)
			if err != nil {
				log.Errorf("ringbuf decode data failed: %v", err)
				continue
			}
			log.Infof("%v", le.Msg)
		}
	}
}

// 4 is the msg length, -1 is the '\0' terminate character
func decodeRecord(data []byte) (*LogEvent, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data length too short: %d", len(data))
	}

	le := LogEvent{}
	lenOfMsg := binary.NativeEndian.Uint32(data[0:4])
	if lenOfMsg < 1 {
		return nil, fmt.Errorf("invalid message length: %d", lenOfMsg)
	}

	if uint32(len(data)) < 4+lenOfMsg {
		return nil, fmt.Errorf("data length %d less than expected %d", len(data), 4+lenOfMsg)
	}

	le.len = uint32(lenOfMsg)
	le.Msg = string(data[4 : 4+lenOfMsg-1])
	return &le, nil
}
