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

package workload

import (
	"sync/atomic"

	"istio.io/pkg/env"
)

var (
	// enableDNSProxyEnv reads from environment variable for backward compatibility
	enableDNSProxyEnv = env.Register("KMESH_ENABLE_DNS_PROXY", false, "When DNS proxy is enabled, a DNS server will be started in kmesh daemon"+
		"and serve DNS requests. DNS requests of kmesh-managed pods will be redirected to kmesh daemon.").Get()

	// enableDNSProxy indicates whether DNS proxy is enabled.
	// This can be set via --enable-dns-proxy flag or KMESH_ENABLE_DNS_PROXY env variable.
	// Flag takes precedence over environment variable.
	// Using atomic.Bool for thread-safe access since this is read from HTTP handlers.
	enableDNSProxy atomic.Bool
)

func init() {
	enableDNSProxy.Store(enableDNSProxyEnv)
}

// EnableDNSProxy returns whether DNS proxy is currently enabled.
// This is thread-safe for concurrent access.
func EnableDNSProxy() bool {
	return enableDNSProxy.Load()
}

// SetEnableDNSProxy sets the EnableDNSProxy flag value.
// This is called from the controller when --enable-dns-proxy flag is provided.
// This is thread-safe for concurrent access.
func SetEnableDNSProxy(enabled bool) {
	enableDNSProxy.Store(enabled)
}
