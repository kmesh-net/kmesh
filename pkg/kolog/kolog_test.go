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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetBootTime(t *testing.T) {
	bootTime, err := getBootTime()
	if err != nil {
		t.Skipf("skipping getBootTime test: %v", err)
	}
	assert.False(t, bootTime.IsZero())
	assert.True(t, bootTime.Before(time.Now()))
}

func TestTimeParse(t *testing.T) {
	bootTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	timestamp := uint64(5_000_000) // 5 seconds in microseconds
	parsedTime := timeParse(timestamp, bootTime)
	expectedTime := bootTime.Add(5 * time.Second)
	assert.Equal(t, expectedTime, parsedTime)
}

func TestParseKmsgLine(t *testing.T) {
	bootTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	appStartTimestamp := uint64(1_000_000)

	t.Run("malformed line", func(t *testing.T) {
		parseKmsgLine("short,line", bootTime, appStartTimestamp)
	})

	t.Run("invalid timestamp", func(t *testing.T) {
		parseKmsgLine("6,100,invalid_ts,flags;message", bootTime, appStartTimestamp)
	})

	t.Run("timestamp before app start", func(t *testing.T) {
		parseKmsgLine("6,100,500000,flags;Kmesh_module log message", bootTime, appStartTimestamp)
	})

	t.Run("valid kmesh module line", func(t *testing.T) {
		parseKmsgLine("6,100,2000000,flags;Kmesh_module initialized\n", bootTime, appStartTimestamp)
	})
}
