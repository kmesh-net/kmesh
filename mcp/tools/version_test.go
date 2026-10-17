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

package tools

import (
	"context"
	"testing"

	"kmesh.net/kmesh/pkg/version"
)

func TestKmeshVersion(t *testing.T) {
	_, output, err := KmeshVersion(
		context.Background(),
		nil,
		VersionInput{},
	)
	if err != nil {
		t.Fatalf("KmeshVersion returned error: %v", err)
	}

	expected := version.Get()

	if output.Version != expected.GitVersion {
		t.Errorf("version = %q, want %q", output.Version, expected.GitVersion)
	}

	if output.Commit != expected.GitCommit {
		t.Errorf("commit = %q, want %q", output.Commit, expected.GitCommit)
	}

	if output.TreeState != expected.GitTreeState {
		t.Errorf("treeState = %q, want %q", output.TreeState, expected.GitTreeState)
	}

	if output.BuildDate != expected.BuildDate {
		t.Errorf("buildDate = %q, want %q", output.BuildDate, expected.BuildDate)
	}

	if output.GoVersion != expected.GoVersion {
		t.Errorf("goVersion = %q, want %q", output.GoVersion, expected.GoVersion)
	}

	if output.Compiler != expected.Compiler {
		t.Errorf("compiler = %q, want %q", output.Compiler, expected.Compiler)
	}

	if output.Platform != expected.Platform {
		t.Errorf("platform = %q, want %q", output.Platform, expected.Platform)
	}
}
