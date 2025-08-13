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

package bpfcache

import (
	"errors"

	"github.com/cilium/ebpf"
)

type WaypointKey struct {
	Addr [16]byte
}

func (c *Cache) WaypointUpdate(key *WaypointKey, value *uint32) error {
	log.Debugf("WaypointUpdate [%#v]", *key)
	return c.bpfMap.KmWaypoint.Update(key, value, ebpf.UpdateAny)
}

func (c *Cache) WaypointDelete(key *WaypointKey) error {
	log.Debugf("WaypointDelete [%#v]", *key)
	err := c.bpfMap.KmWaypoint.Delete(key)
	if err != nil && errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}
