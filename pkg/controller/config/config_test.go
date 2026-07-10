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

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewXDSConfig(t *testing.T) {
	t.Setenv("INSTANCE_IP", "10.244.0.81")
	t.Setenv("POD_NAME", "test")
	t.Setenv("POD_NAMESPACE", "testNs")
	t.Setenv("XDS_ADDRESS", "istiod.istio-system.svc:15012")

	config, err := NewXDSConfig("ads")
	require.NoError(t, err)
	assert.Equal(t, "sidecar~10.244.0.81~test.testNs~testNs.svc.cluster.local", config.ServiceNode)
	assert.Equal(t, "istiod.istio-system.svc:15012", config.DiscoveryAddress)
	assert.Equal(t, []string{"10.244.0.81"}, config.Metadata.InstanceIPs)
}

func TestNewXDSConfigRequiresInstanceIP(t *testing.T) {
	t.Setenv("INSTANCE_IP", "")
	t.Setenv("POD_NAME", "test")
	t.Setenv("POD_NAMESPACE", "testNs")

	config, err := NewXDSConfig("ads")
	require.Error(t, err)
	assert.Nil(t, config)
	assert.EqualError(t, err, "INSTANCE_IP must be set for XDS bootstrap")
}
