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

package utils

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
)

func TestProgramOptionsForVerifierLog(t *testing.T) {
	// Disabled (default) level must return the zero value, preserving
	// default program load behavior.
	assert.Equal(t, ebpf.ProgramOptions{}, ProgramOptionsForVerifierLog(0))

	opts := ProgramOptionsForVerifierLog(3)
	assert.Equal(t, ebpf.LogLevel(3), opts.LogLevel)
	assert.Equal(t, uint32(VerifierLogSize), opts.LogSizeStart)
}

type testPrograms struct {
	Foo *ebpf.Program
	Bar *ebpf.Program
	Baz *ebpf.Program
}

func TestLogVerifierOutput(t *testing.T) {
	progs := testPrograms{
		Foo: &ebpf.Program{VerifierLog: "foo verifier output"},
		Bar: &ebpf.Program{}, // loaded, but no captured output
		Baz: nil,             // never loaded
	}

	var logged []string
	logf := func(format string, args ...interface{}) {
		logged = append(logged, fmt.Sprintf(format, args...))
	}

	value := reflect.ValueOf(progs)
	LogVerifierOutput(&value, logf)

	if assert.Len(t, logged, 1) {
		assert.Contains(t, logged[0], "Foo")
		assert.Contains(t, logged[0], "foo verifier output")
	}
}

func TestLogVerifierOutputNoop(t *testing.T) {
	progs := testPrograms{}

	logf := func(format string, args ...interface{}) {
		t.Fatalf("logf should not be called when no verifier output was captured")
	}

	value := reflect.ValueOf(progs)
	LogVerifierOutput(&value, logf)
}
