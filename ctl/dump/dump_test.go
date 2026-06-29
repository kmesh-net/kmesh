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

package dump

import (
	"testing"
)

func TestNewCmd(t *testing.T) {
	cmd := NewCmd()
	if cmd.Use != "dump [kmesh-daemon-pod] <mode>" {
		t.Errorf("unexpected Use: %s", cmd.Use)
	}

	// Verify flag
	flag := cmd.Flag("output")
	if flag == nil {
		t.Fatal("expected 'output' flag to be registered")
	}
	if flag.Shorthand != "o" {
		t.Errorf("expected shorthand 'o', got %s", flag.Shorthand)
	}
}
