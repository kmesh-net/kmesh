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

package auth

import (
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"kmesh.net/kmesh/pkg/constants"
)

func Test_xdpNotifyConnRst(t *testing.T) {
	err := rlimit.RemoveMemlock()
	require.NoError(t, err, "failed to remove memlock")

	mapOfAuth, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "test_map_of_auth_result",
		Type:       ebpf.Hash,
		KeySize:    uint32(TUPLE_LEN),
		ValueSize:  uint32(unsafe.Sizeof(uint32(0))),
		MaxEntries: 4096,
	})
	require.NoError(t, err, "failed to create ebpf map")
	defer mapOfAuth.Close()

	t.Run("nil map", func(t *testing.T) {
		key := make([]byte, TUPLE_LEN)
		err := xdpNotifyConnRst(nil, constants.MSG_TYPE_IPV4, key)
		assert.Error(t, err)
		assert.Equal(t, "map_of_auth_result is nil", err.Error())
	})

	t.Run("IPv4 zeros out remainder and inserts", func(t *testing.T) {
		key := make([]byte, TUPLE_LEN)
		// fill with some garbage
		for i := 0; i < len(key); i++ {
			key[i] = 0xAA
		}

		err := xdpNotifyConnRst(mapOfAuth, constants.MSG_TYPE_IPV4, key)
		assert.NoError(t, err)

		// check that remainder is zeroed
		for i := IPV4_TUPLE_LENGTH; i < len(key); i++ {
			assert.Equal(t, byte(0), key[i], "byte at index %d should be 0", i)
		}

		// check that map contains the key
		var val uint32
		err = mapOfAuth.Lookup(key, &val)
		assert.NoError(t, err)
		assert.Equal(t, uint32(1), val)
	})

	t.Run("IPv6 does not zero out remainder and inserts", func(t *testing.T) {
		key := make([]byte, TUPLE_LEN)
		for i := 0; i < len(key); i++ {
			key[i] = 0xBB
		}

		// copy key for assertion later
		expectedKey := make([]byte, TUPLE_LEN)
		copy(expectedKey, key)

		err := xdpNotifyConnRst(mapOfAuth, constants.MSG_TYPE_IPV6, key)
		assert.NoError(t, err)

		// check that key is unmodified
		assert.Equal(t, expectedKey, key)

		// check that map contains the key
		var val uint32
		err = mapOfAuth.Lookup(key, &val)
		assert.NoError(t, err)
		assert.Equal(t, uint32(1), val)
	})
}
