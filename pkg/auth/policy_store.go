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
	"fmt"
	"sync"

	"istio.io/istio/pkg/util/sets"

	"kmesh.net/kmesh/api/v2/workloadapi/security"
)

type policyStore struct {
	// byKey maintains a mapping of ns/name to policy
	byKey map[string]*security.Authorization

	// byNamespace maintains a mapping of namespace (or "" for global) to policy names
	byNamespace map[string]sets.Set[string]

	rwLock sync.RWMutex
}

func newPolicyStore() *policyStore {
	return &policyStore{
		byKey:       make(map[string]*security.Authorization),
		byNamespace: make(map[string]sets.Set[string]),
	}
}

func (ps *policyStore) updatePolicy(authPolicy *security.Authorization) error {
	if authPolicy == nil {
		return nil
	}
	key := authPolicy.ResourceName()

	// Validate the scope before mutating any index so a rejected update
	// cannot leave the store in a partially modified state.
	switch authPolicy.GetScope() {
	case security.Scope_WORKLOAD_SELECTOR, security.Scope_GLOBAL, security.Scope_NAMESPACE:
	default:
		return fmt.Errorf("invalid scope %v of authorization policy", authPolicy.GetScope())
	}

	ps.rwLock.Lock()
	defer ps.rwLock.Unlock()

	// A policy may change scope on update (e.g. NAMESPACE -> GLOBAL). Unlink the
	// previously stored version first so no stale namespace/global index entry
	// is left pointing at it.
	if old, ok := ps.byKey[key]; ok {
		ps.unlinkPolicyLocked(key, old)
	}

	ps.linkPolicyLocked(key, authPolicy)
	ps.byKey[key] = authPolicy
	return nil
}

func (ps *policyStore) removePolicy(policyKey string) {
	ps.rwLock.Lock()
	defer ps.rwLock.Unlock()

	authPolicy, ok := ps.byKey[policyKey]
	if !ok {
		log.Warnf("Auth policy key %s does not exist in byKey", policyKey)
		return
	}
	// remove authPolicy from byKey
	delete(ps.byKey, policyKey)
	ps.unlinkPolicyLocked(policyKey, authPolicy)
}

// namespaceIndexKey returns the byNamespace key for a policy and whether the
// policy is tracked in the namespace index at all. WORKLOAD_SELECTOR scoped
// policies are only tracked in byKey, so they report ok=false.
func namespaceIndexKey(authPolicy *security.Authorization) (string, bool) {
	switch authPolicy.GetScope() {
	case security.Scope_GLOBAL:
		return "", true
	case security.Scope_NAMESPACE:
		return authPolicy.GetNamespace(), true
	default:
		return "", false
	}
}

// linkPolicyLocked adds the policy key to the namespace index for its current
// scope. Callers must hold rwLock.
func (ps *policyStore) linkPolicyLocked(key string, authPolicy *security.Authorization) {
	ns, ok := namespaceIndexKey(authPolicy)
	if !ok {
		return
	}
	if s, ok := ps.byNamespace[ns]; ok {
		s.Insert(key)
	} else {
		ps.byNamespace[ns] = sets.New(key)
	}
}

// unlinkPolicyLocked removes the policy key from the namespace index for the
// scope of the supplied policy, pruning the namespace bucket when it becomes
// empty. Callers must hold rwLock.
func (ps *policyStore) unlinkPolicyLocked(key string, authPolicy *security.Authorization) {
	ns, ok := namespaceIndexKey(authPolicy)
	if !ok {
		return
	}
	if s, ok := ps.byNamespace[ns]; ok {
		s.Delete(key)
		if s.IsEmpty() {
			delete(ps.byNamespace, ns)
		}
	}
}

// getAllPolicies returns a copied set of all policy names
func (ps *policyStore) getAllPolicies() map[string]string {
	ps.rwLock.RLock()
	defer ps.rwLock.RUnlock()

	out := make(map[string]string, len(ps.byKey))
	for k := range ps.byKey {
		out[k] = ""
	}
	return out
}

// getByNamespace returns a copied set of policy name in namespace, or an empty set if namespace not exists
func (ps *policyStore) getByNamespace(namespace string) []string {
	ps.rwLock.RLock()
	defer ps.rwLock.RUnlock()

	if s, ok := ps.byNamespace[namespace]; ok {
		return s.UnsortedList()
	}
	return nil
}

// List returns a copied list of all policies
func (p *policyStore) list() []*security.Authorization {
	p.rwLock.RLock()
	defer p.rwLock.RUnlock()
	out := make([]*security.Authorization, 0, len(p.byKey))
	for _, pol := range p.byKey {
		out = append(out, pol)
	}

	return out
}
