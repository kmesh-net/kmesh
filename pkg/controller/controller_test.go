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

package controller

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"kmesh.net/kmesh/daemon/options"
)

func TestControllerStop(t *testing.T) {
	t.Run("nil controller", func(t *testing.T) {
		var c *Controller
		assert.NotPanics(t, func() {
			c.Stop()
		})
	})

	t.Run("nil client and nil dnsServer", func(t *testing.T) {
		c := &Controller{
			bpfConfig: &options.BpfConfig{
				EnableIPsec: false,
			},
			client:    nil,
			dnsServer: nil,
		}
		assert.NotPanics(t, func() {
			c.Stop()
		})
	})

	t.Run("non-nil client with nil WorkloadController", func(t *testing.T) {
		c := &Controller{
			bpfConfig: &options.BpfConfig{
				EnableIPsec: false,
			},
			client:    &XdsClient{},
			dnsServer: nil,
		}
		assert.NotPanics(t, func() {
			c.Stop()
		})
	})
}
