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
	"strconv"
	"strings"
	"syscall"
)

// KernelVersionLowerThan5_13 return whether the current kernel version is lower than 5.13,
// and will fallback to less BPF log ability(return true) if error
func KernelVersionLowerThan5_13() bool {
	kernelVersion := GetKernelVersion()
	if len(kernelVersion) == 0 {
		return true
	}
	splitVers := strings.Split(kernelVersion, ".")
	if len(splitVers) < 2 {
		return true
	}

	mainVer, err := strconv.Atoi(splitVers[0])
	if err != nil || mainVer < 5 {
		return true
	}
	if mainVer > 5 {
		return false
	}

	subVer, err := strconv.Atoi(splitVers[1])
	return err != nil || subVer < 13
}

// GetKernelVersion return part of the result of 'uname -a' like '5.15.153.1-xxxx'
func GetKernelVersion() string {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return ""
	}
	return int8ToStr(uname.Release[:])
}

func int8ToStr(arr []int8) string {
	b := make([]byte, 0, len(arr))
	for _, v := range arr {
		if v == 0x00 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}
