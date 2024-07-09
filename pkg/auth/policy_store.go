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

	ps.rwLock.Lock()
	defer ps.rwLock.Unlock()
	var ns string
	switch authPolicy.GetScope() {
	case security.Scope_WORKLOAD_SELECTOR:
		ps.byKey[key] = authPolicy
		return nil
	case security.Scope_GLOBAL:
		ns = ""
	case security.Scope_NAMESPACE:
		ns = authPolicy.GetNamespace()
	default:
		return fmt.Errorf("invalid scope %v of authorization policy", authPolicy.GetScope())
	}

	if s, ok := ps.byNamespace[ns]; !ok {
		ps.byNamespace[ns] = sets.New(key)
	} else {
		s.Insert(key)
	}
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

	var ns string
	switch authPolicy.Scope {
	case security.Scope_GLOBAL:
		ns = ""
	case security.Scope_NAMESPACE:
		ns = authPolicy.GetNamespace()
	default:
		return
	}

	// remove authPolicy key from byNamespace
	if s, ok := ps.byNamespace[ns]; ok {
		s.Delete(policyKey)
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
