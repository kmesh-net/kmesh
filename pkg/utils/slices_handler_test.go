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
 *
 */

package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompareIpByte(t *testing.T) {
	t.Run("Ipv4 compare test", func(t *testing.T) {
		newData := [][]byte{
			{1, 1, 1, 1},
			{2, 2, 2, 2},
		}
		oldData := [][]byte{
			{3, 3, 3, 3},
			{2, 2, 2, 2},
		}

		aNew, bMissing := CompareIpByte(newData, oldData)
		expectedAdd := [][]byte{
			{1, 1, 1, 1},
		}
		expectedMissing := [][]byte{
			{3, 3, 3, 3},
		}
		assert.Equal(t, expectedAdd, aNew)
		assert.Equal(t, expectedMissing, bMissing)
	})

	t.Run("Ipv6 compare test", func(t *testing.T) {
		newData := [][]byte{
			{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
		}
		oldData := [][]byte{
			{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
			{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
		}

		aNew, bMissing := CompareIpByte(newData, oldData)
		expectedAdd := [][]byte{
			{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		}
		expectedMissing := [][]byte{
			{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
		}
		assert.Equal(t, expectedAdd, aNew)
		assert.Equal(t, expectedMissing, bMissing)
	})
}
