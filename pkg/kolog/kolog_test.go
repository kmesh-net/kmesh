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
)

func TestCanWatchKmsg(t *testing.T) {
	if canWatchKmsg(time.Time{}) {
		t.Error("canWatchKmsg(zero time) = true, want false")
	}
	if !canWatchKmsg(time.Now()) {
		t.Error("canWatchKmsg(real time) = false, want true")
	}
}

func TestTimeParse(t *testing.T) {
	boot := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	got := timeParse(2_500_000, boot) // 2.5s in kmsg microseconds
	want := boot.Add(2500 * time.Millisecond)
	if !got.Equal(want) {
		t.Errorf("timeParse() = %v, want %v", got, want)
	}
}
