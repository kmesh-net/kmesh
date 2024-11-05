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

package ads

import (
	"os"
	cache_v2 "kmesh.net/kmesh/pkg/cache/v2"
	maps_v2 "kmesh.net/kmesh/pkg/cache/v2/maps"
	"sigs.k8s.io/yaml"
)

const (
	persistPath = "/mnt/kernel_native_hash_name.yaml"
)

// HashName converts a string to a uint32 integer as the key of bpf map
type HashName struct {
	NameToCds map[string][2]uint64
	NameToLds map[string]uint64
	NameToRds map[string]uint64
}

// HashName creates a new HashName instance
func NewHashName() *HashName {
	return &HashName{
		NameToCds: make(map[string][2]uint64),
		NameToLds: make(map[string]uint64),
		NameToRds: make(map[string]uint64),
	}
}

func ReadFromPersistFile(h *HashName) error {
	data, err := os.ReadFile(persistPath)
	if err != nil {
		return nil
	}

	return yaml.Unmarshal(data, h)
}

func WritePersistFile(h *HashName) error {
	data, err := yaml.Marshal(h)
	if err != nil {
		return err
	}

	return os.WriteFile(persistPath, data, 0644)
}

// Should only be used by test
func ResetPersistFile() {
	os.Remove(persistPath)
}

func HandleRemovedCdsAndEdsDuringRestart(cache *cache_v2.ClusterCache) error {
	hashName := NewHashName()
	if ReadFromPersistFile(hashName) != nil {
		return nil
	}

	for key := range hashName.NameToCds {
		if cache.GetEdsHash(key) == 0 {
			err := maps_v2.ClusterDelete(key)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func HandleRemovedLdsDuringRestart(cache *cache_v2.ListenerCache) error {
	hashName := NewHashName()
	if ReadFromPersistFile(hashName) != nil {
		return nil
	}
	for key := range hashName.NameToLds {
		if cache.GetLdsHash(key) == 0 {
			listener := cache.GetApiListener(key)
			err := maps_v2.ListenerDelete(listener.GetAddress())
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func HandleRemovedRdsDuringRestart(cache *cache_v2.RouteConfigCache) error {
	hashName := NewHashName()
	if ReadFromPersistFile(hashName) != nil {
		return nil
	}
	for key := range hashName.NameToRds {
		if cache.GetRdsHash(key) == 0 {
			err := maps_v2.RouteConfigDelete(key)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
