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
	"testing"

	"kmesh.net/kmesh/pkg/utils"
)

func TestDecodeEbpfLog(t *testing.T) {
	c := &BpfLogController{hash: utils.NewHashName()} // Create an instance of BpfLogController for testing

	svchash := c.hash.Hash("test.default.svc.cluster.local") // Hash the string "test.default.svc.cluster.local"
	podhash := c.hash.Hash("default/test")                   // Hash the string "test.default.svc.cluster.local"
	type testCase struct {
		name        string
		msg         string
		err         bool
		expectedLog string
	}
	testCases := []testCase{
		{
			name:        "valid bpf log message with service ID prefix",
			msg:         fmt.Sprintf("%s %d %s", SERVICE_ID, svchash, "service message"),
			err:         false,
			expectedLog: "[SERVICE_ID] test.default.svc.cluster.local service message",
		},
		{
			name:        "valid bpf log message with service ID prefix",
			msg:         fmt.Sprintf("%s %d %s", SERVICE_ID, svchash, "service message"),
			err:         false,
			expectedLog: "[SERVICE_ID] test.default.svc.cluster.local service message",
		},
		{
			name:        "valid bpf log message with backend ID prefix",
			msg:         fmt.Sprintf("[SERVICE] DEBUG: %s %d %s", BACKEND_UID, podhash, "backend message"),
			err:         false,
			expectedLog: "[SERVICE] DEBUG: [BACKEND_UID] default/test backend message",
		},
		{
			name:        "valid bpf log message with backend ID prefix",
			msg:         fmt.Sprintf("[SERVICE] DEBUG: %s %d %s", BACKEND_UID, podhash, "backend message"),
			err:         false,
			expectedLog: "[SERVICE] DEBUG: [BACKEND_UID] default/test backend message",
		},
		{
			name:        "valid bpf log message with backend ID prefix but no hash found",
			msg:         fmt.Sprintf("%s %d %s", BACKEND_UID, 4678, "backend message"),
			err:         false,
			expectedLog: "[BACKEND_UID] 4678 backend message",
		},
		{
			name:        "invalid bpf log message",
			msg:         "invalid bpf log message",
			err:         true,
			expectedLog: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var data []byte
			if !tc.err {
				data = make([]byte, 4+len(tc.msg))
				binary.NativeEndian.PutUint32(data, uint32(len(tc.msg)))
				copy(data[4:], []byte(tc.msg))
			} else {
				// invalid length
				data = []byte(tc.msg)
			}
			msg, err := c.decodeEbpfLog(data)
			if tc.err && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.err && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if tc.expectedLog != msg {
				t.Errorf("expected %v, got %v", tc.expectedLog, msg)
			}

		})
	}

}
