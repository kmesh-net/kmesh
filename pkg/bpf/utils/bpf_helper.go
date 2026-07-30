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
	"os"
	"reflect"
	"strconv"

	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// VerifierLogSize is the starting size, in bytes, of the verifier log buffer
// used when BPF verifier logging is enabled. It is sized generously so the
// full verifier output for kmesh's BPF programs can be captured without
// relying on the ebpf library's automatic buffer-doubling retries.
const VerifierLogSize = 10 * 1024 * 1024

// ProgramOptionsForVerifierLog returns the ebpf.ProgramOptions needed to
// capture verifier output at the given log level. A level of 0 returns the
// zero value, leaving default (no verifier logging) program load behavior
// unchanged.
func ProgramOptionsForVerifierLog(level uint32) ebpf.ProgramOptions {
	if level == 0 {
		return ebpf.ProgramOptions{}
	}
	return ebpf.ProgramOptions{
		LogLevel:     ebpf.LogLevel(level),
		LogSizeStart: VerifierLogSize,
	}
}

// LogVerifierOutput logs the captured eBPF verifier output for each
// *ebpf.Program field in value (a bpf2go-generated *Programs struct).
// Fields with no captured output (verifier logging disabled or load
// skipped it) are left untouched.
func LogVerifierOutput(value *reflect.Value, logf func(format string, args ...interface{})) {
	for i := 0; i < value.NumField(); i++ {
		prog, ok := value.Field(i).Interface().(*ebpf.Program)
		if !ok || prog == nil || prog.VerifierLog == "" {
			continue
		}
		logf("bpf verifier log for %s:\n%s", value.Type().Field(i).Name, prog.VerifierLog)
	}
}

func SetEnvByBpfMapId(m *ebpf.Map, key string) error {
	info, _ := m.Info()
	id, _ := info.ID()
	stringId := strconv.Itoa(int(id))
	return os.Setenv(key, stringId)
}

func BpfProgUpdate(pinPath string, cgopt link.CgroupOptions) (link.Link, error) {
	sclink, err := link.LoadPinnedLink(pinPath, &ebpf.LoadPinOptions{})
	if err != nil {
		return nil, err
	}
	if err := sclink.Update(cgopt.Program); err != nil {
		return nil, fmt.Errorf("updating link %s failed: %w", pinPath, err)
	}
	return sclink, nil
}
