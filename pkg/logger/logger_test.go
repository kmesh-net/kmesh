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
	"strings"
	"testing"
)

func TestDecodeRecord(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    []byte
		wantMsg string
		wantLen uint32
		wantErr string
	}{
		{
			name:    "short sample",
			data:    []byte{1, 2, 3},
			wantErr: "too short",
		},
		{
			name:    "zero message length",
			data:    makeRecord(0),
			wantErr: "invalid message length",
		},
		{
			name:    "oversized message length",
			data:    append(makeRecord(8), []byte("hi\x00")...),
			wantErr: "exceeds sample size",
		},
		{
			name:    "empty message",
			data:    append(makeRecord(1), 0),
			wantLen: 1,
		},
		{
			name:    "valid message",
			data:    append(makeRecord(6), []byte("hello\x00")...),
			wantMsg: "hello",
			wantLen: 6,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := decodeRecord(tt.data)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("decodeRecord() error = nil, want %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("decodeRecord() error = %q, want substring %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeRecord() unexpected error = %v", err)
			}
			if got.len != tt.wantLen {
				t.Fatalf("decodeRecord() len = %d, want %d", got.len, tt.wantLen)
			}
			if got.Msg != tt.wantMsg {
				t.Fatalf("decodeRecord() msg = %q, want %q", got.Msg, tt.wantMsg)
			}
		})
	}
}

func makeRecord(msgLen uint32) []byte {
	data := make([]byte, recordLenSize)
	binary.NativeEndian.PutUint32(data, msgLen)
	return data
}
