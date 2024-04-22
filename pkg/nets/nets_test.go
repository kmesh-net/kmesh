/*
 * Copyright 2024 The Kmesh Authors.
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

package nets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ConvertIpToUint32(t *testing.T) {
	ip := "192.168.0.1"
	val := ConvertIpToUint32(ip)
	assert.Equal(t, 0x100a8c0, val)

	// It can not panic even for invalid ip
	val = ConvertIpToUint32("a.b.c.d")
	assert.Equal(t, uint32(0), val)
}
