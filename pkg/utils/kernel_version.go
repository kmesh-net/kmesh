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
)

// KernelVersionLowerThan5_13 return whether the current kernel version is lower than 5.13,
// and will fallback to less BPF log ability(return true) if error
func KernelVersionLowerThan5_13() bool {
	return isVersionLowerThan(GetKernelVersion(), 5, 13)
}

func isVersionLowerThan(kernelVersion string, major, minor int) bool {
	if len(kernelVersion) == 0 {
		return true
	}
	splitVers := strings.Split(kernelVersion, ".")
	if len(splitVers) < 2 {
		return true
	}

	mainVer, err := strconv.Atoi(splitVers[0])
	if err != nil || mainVer < major {
		return true
	}
	if mainVer > major {
		return false
	}

	subVer, err := strconv.Atoi(splitVers[1])
	return err != nil || subVer < minor
}
