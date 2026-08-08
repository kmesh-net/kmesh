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

package common

import (
	"testing"
)

func TestGetRootCommand(t *testing.T) {
	rootCmd := GetRootCommand()

	if rootCmd.Use != "kmeshctl" {
		t.Fatalf("Use = %q, want %q", rootCmd.Use, "kmeshctl")
	}
	if !rootCmd.SilenceUsage {
		t.Fatal("SilenceUsage should be true")
	}
	if !rootCmd.CompletionOptions.DisableDefaultCmd {
		t.Fatal("default completion command should be disabled")
	}

	want := map[string]bool{
		"log": false, "dump": false, "waypoint": false, "version": false,
		"monitoring": false, "authz": false, "secret": false,
	}
	for _, cmd := range rootCmd.Commands() {
		if _, ok := want[cmd.Name()]; ok {
			want[cmd.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("subcommand %q not registered", name)
		}
	}
}
