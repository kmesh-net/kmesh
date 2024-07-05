//go:build !linux
// +build !linux

// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dependencies

import (
	"errors"
	"io"

	"istio.io/istio/tools/istio-iptables/pkg/constants"
)

// ErrNotImplemented is returned when a requested feature is not implemented.
var ErrNotImplemented = errors.New("not implemented")

func (r *RealDependencies) execute(cmd string, ignoreErrors bool, stdin io.Reader, args ...string) error {
	return ErrNotImplemented
}

func (r *RealDependencies) executeXTables(cmd constants.IptablesCmd, iptVer *IptablesVersion, ignoreErrors bool, stdin io.ReadSeeker, args ...string) error {
	return ErrNotImplemented
}

func shouldUseBinaryForCurrentContext(iptablesBin string) (IptablesVersion, error) {
	return IptablesVersion{}, ErrNotImplemented
}
