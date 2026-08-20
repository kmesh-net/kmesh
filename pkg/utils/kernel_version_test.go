//go:build linux
// +build linux

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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInt8ToStr(t *testing.T) {
	arr := []int8{'5', '.', '1', '5', 0, 'x'}
	res := int8ToStr(arr)
	assert.Equal(t, "5.15", res)
}

func TestGetKernelVersion(t *testing.T) {
	version := GetKernelVersion()
	assert.NotNil(t, version)
}

func TestKernelVersionLowerThan5_13(t *testing.T) {
	res := KernelVersionLowerThan5_13()
	_ = res
}
