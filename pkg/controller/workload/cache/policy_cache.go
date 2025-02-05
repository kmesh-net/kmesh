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

package cache

import (
	"sync"

	"kmesh.net/kmesh/api/v2/workloadapi/security"
)

type PolicyCache interface {
	List() []*security.Authorization
	AddOrUpdatePolicy(policy *security.Authorization)
	DeletePolicy(resourceName string)
	GetPolicy(resourceName string) *security.Authorization
}

var _ PolicyCache = &policyCache{}

type policyCache struct {
	mutex sync.RWMutex

	policiesByResourceName map[string]*security.Authorization
}

func NewPolicyCache() *policyCache {
	return &policyCache{
		policiesByResourceName: make(map[string]*security.Authorization),
	}
}

func (p *policyCache) GetPolicy(resourceName string) *security.Authorization {
	p.mutex.RLock()
	defer p.mutex.Unlock()
	return p.policiesByResourceName[resourceName]
}

func (p *policyCache) AddOrUpdatePolicy(policy *security.Authorization) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	resourceName := policy.ResourceName()

	p.policiesByResourceName[resourceName] = policy
}

func (p *policyCache) DeletePolicy(resourceName string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	delete(p.policiesByResourceName, resourceName)
}

func (p *policyCache) List() []*security.Authorization {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	out := make([]*security.Authorization, 0, len(p.policiesByResourceName))
	for _, pol := range p.policiesByResourceName {
		out = append(out, pol)
	}

	return out
}
