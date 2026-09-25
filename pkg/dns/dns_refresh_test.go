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

package dns

import (
	"testing"
	"time"

	"k8s.io/client-go/util/workqueue"
)

// TestRefreshDnsRequeuesOnResolveFailure verifies that a transient resolve
// failure does not permanently stop a domain from being refreshed.
//
// refreshDns re-queues a domain after a successful resolve (AddAfter on the
// success path). It must also re-queue after a failed resolve, otherwise a
// single upstream hiccup consumes the domain's queue entry via Get/Done and
// nothing ever re-adds it, freezing that domain's cached addresses forever.
func TestRefreshDnsRequeuesOnResolveFailure(t *testing.T) {
	r := &DNSResolver{
		DnsChan:      make(chan string, 100),
		cache:        map[string]*DomainCacheEntry{},
		refreshQueue: workqueue.NewTypedDelayingQueueWithConfig(workqueue.TypedDelayingQueueConfig[any]{Name: "test-refresh"}),
		// No delegate resolvers, so every resolve returns SERVFAIL and fails.
		delegates: []Resolver{},
	}
	defer r.refreshQueue.ShutDown()

	const domain = "always-fails.kmesh.test."
	// The domain is watched (present in cache) so refreshDns does not early-return;
	// the resolve itself is what fails.
	r.cache[domain] = &DomainCacheEntry{}
	e := &DomainInfo{Domain: domain, RefreshRate: 10 * time.Second}

	// Enqueue once; refreshDns consumes it and hits the resolve-failure path.
	r.refreshQueue.AddAfter(e, 0)
	r.refreshDns()

	// A correct refresher re-queues the domain after the failure (RetryAfter) so
	// it keeps trying. Give the delaying queue time to surface the re-queued item.
	time.Sleep(RetryAfter + 100*time.Millisecond)
	if got := r.refreshQueue.Len(); got != 1 {
		t.Fatalf("after a failed resolve, refreshDns must re-queue the domain so it keeps refreshing later; refreshQueue.Len() = %d, want 1", got)
	}
}
