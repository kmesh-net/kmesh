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

package cache_v2

import (
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"
	"istio.io/istio/pkg/slices"

	core_v2 "kmesh.net/kmesh/api/v2/core"
	listener_v2 "kmesh.net/kmesh/api/v2/listener"
	maps_v2 "kmesh.net/kmesh/pkg/cache/v2/maps"
	"kmesh.net/kmesh/pkg/utils/hash"
)

func TestListenerFlush(t *testing.T) {
	t.Run("listener status is UPDATE", func(t *testing.T) {
		updateListenerAddress := []*core_v2.SocketAddress{}
		deleteListenerAddress := []*core_v2.SocketAddress{}

		patches1 := gomonkey.NewPatches()
		patches2 := gomonkey.NewPatches()
		patches1.ApplyFunc(maps_v2.ListenerUpdate, func(key *core_v2.SocketAddress, value *listener_v2.Listener) error {
			updateListenerAddress = append(updateListenerAddress, key)
			return nil
		})
		patches1.ApplyFunc(maps_v2.ListenerDelete, func(key *core_v2.SocketAddress) error {
			deleteListenerAddress = append(deleteListenerAddress, key)
			return nil
		})
		defer func() {
			patches1.Reset()
			patches2.Reset()
		}()
		cache := NewListenerCache()
		listener1 := &listener_v2.Listener{
			ApiStatus: core_v2.ApiStatus_UPDATE,
			Name:      "ut-listener1",
			Address: &core_v2.SocketAddress{
				Protocol: core_v2.SocketAddress_TCP,
				Port:     uint32(80),
			},
		}
		listener2 := &listener_v2.Listener{
			ApiStatus: core_v2.ApiStatus_UPDATE,
			Name:      "ut-listener2",
			Address: &core_v2.SocketAddress{
				Protocol: core_v2.SocketAddress_TCP,
				Port:     uint32(81),
			},
		}
		cache.SetApiListener(listener1.Name, listener1)
		cache.SetApiListener(listener2.Name, listener2)
		cache.Flush()
		apiListener1 := cache.GetApiListener(listener1.Name)
		apiListener2 := cache.GetApiListener(listener2.Name)
		assert.Equal(t, core_v2.ApiStatus_NONE, apiListener1.ApiStatus)
		assert.Equal(t, core_v2.ApiStatus_NONE, apiListener2.ApiStatus)
		assert.Equal(t, true, slices.EqualUnordered([]*core_v2.SocketAddress{listener1.GetAddress(), listener2.GetAddress()}, updateListenerAddress))
		assert.Equal(t, []*core_v2.SocketAddress{}, deleteListenerAddress)
	})

	t.Run("one listener status is UPDATE, one listener status is DELETE", func(t *testing.T) {
		updateListenerAddress := []*core_v2.SocketAddress{}
		deleteListenerAddress := []*core_v2.SocketAddress{}

		patches1 := gomonkey.NewPatches()
		patches2 := gomonkey.NewPatches()
		patches1.ApplyFunc(maps_v2.ListenerUpdate, func(key *core_v2.SocketAddress, value *listener_v2.Listener) error {
			updateListenerAddress = append(updateListenerAddress, key)
			return nil
		})
		patches1.ApplyFunc(maps_v2.ListenerDelete, func(key *core_v2.SocketAddress) error {
			deleteListenerAddress = append(deleteListenerAddress, key)
			return nil
		})
		defer func() {
			patches1.Reset()
			patches2.Reset()
		}()
		cache := NewListenerCache()
		listener1 := &listener_v2.Listener{
			ApiStatus: core_v2.ApiStatus_UPDATE,
			Name:      "ut-listener1",
			Address: &core_v2.SocketAddress{
				Protocol: core_v2.SocketAddress_TCP,
				Port:     uint32(80),
			},
		}
		listener2 := &listener_v2.Listener{
			ApiStatus: core_v2.ApiStatus_DELETE,
			Name:      "ut-listener2",
			Address: &core_v2.SocketAddress{
				Protocol: core_v2.SocketAddress_TCP,
				Port:     uint32(81),
			},
		}
		anyListener1, err1 := anypb.New(listener1)
		anyListener2, err2 := anypb.New(listener2)
		assert.NoError(t, err1)
		assert.NoError(t, err2)
		cache.AddOrUpdateLdsHash(listener1.Name, hash.Sum64String(anyListener1.String()))
		cache.AddOrUpdateLdsHash(listener2.Name, hash.Sum64String(anyListener2.String()))
		cache.SetApiListener(listener1.Name, listener1)
		cache.SetApiListener(listener2.Name, listener2)
		cache.Flush()
		apiListener1 := cache.GetApiListener(listener1.Name)
		apiListener2 := cache.GetApiListener(listener2.Name)
		assert.Equal(t, core_v2.ApiStatus_NONE, apiListener1.ApiStatus)
		assert.Nil(t, apiListener2)
		apiLdsHash1 := cache.GetLdsHash(listener1.Name)
		apiLdsHash2 := cache.GetLdsHash(listener2.Name)
		zeroHash := uint64(0)
		assert.Equal(t, hash.Sum64String(anyListener1.String()), apiLdsHash1)
		assert.Equal(t, zeroHash, apiLdsHash2)
		assert.Equal(t, []*core_v2.SocketAddress{listener1.GetAddress()}, updateListenerAddress)
		assert.Equal(t, []*core_v2.SocketAddress{listener2.GetAddress()}, deleteListenerAddress)
	})

	t.Run("listener status isn't UPDATE or DELETE", func(t *testing.T) {
		updateListenerAddress := []*core_v2.SocketAddress{}
		deleteListenerAddress := []*core_v2.SocketAddress{}

		patches1 := gomonkey.NewPatches()
		patches2 := gomonkey.NewPatches()
		patches1.ApplyFunc(maps_v2.ListenerUpdate, func(key *core_v2.SocketAddress, value *listener_v2.Listener) error {
			updateListenerAddress = append(updateListenerAddress, key)
			return nil
		})
		patches1.ApplyFunc(maps_v2.ListenerDelete, func(key *core_v2.SocketAddress) error {
			deleteListenerAddress = append(deleteListenerAddress, key)
			return nil
		})
		defer func() {
			patches1.Reset()
			patches2.Reset()
		}()
		cache := NewListenerCache()
		listener1 := &listener_v2.Listener{
			ApiStatus: core_v2.ApiStatus_UNCHANGED,
			Name:      "ut-listener1",
			Address: &core_v2.SocketAddress{
				Protocol: core_v2.SocketAddress_TCP,
				Port:     uint32(80),
			},
		}
		listener2 := &listener_v2.Listener{
			ApiStatus: core_v2.ApiStatus_ALL,
			Name:      "ut-listener2",
			Address: &core_v2.SocketAddress{
				Protocol: core_v2.SocketAddress_TCP,
				Port:     uint32(81),
			},
		}
		cache.SetApiListener(listener1.Name, listener1)
		cache.SetApiListener(listener2.Name, listener2)
		cache.Flush()
		apiListener1 := cache.GetApiListener(listener1.Name)
		apiListener2 := cache.GetApiListener(listener2.Name)
		assert.Equal(t, core_v2.ApiStatus_UNCHANGED, apiListener1.ApiStatus)
		assert.Equal(t, core_v2.ApiStatus_ALL, apiListener2.ApiStatus)
		assert.Equal(t, []*core_v2.SocketAddress{}, updateListenerAddress)
		assert.Equal(t, []*core_v2.SocketAddress{}, deleteListenerAddress)
	})
}
