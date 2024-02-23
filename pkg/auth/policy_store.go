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
	byKey map[string]authPolicy

	// byNamespace maintains a mapping of namespace (or "" for global) to policy names
	byNamespace map[string]sets.Set[string]

	rwLock sync.RWMutex
}

func newPolicystore() *policyStore {
	return &policyStore{
		byKey:       make(map[string]authPolicy),
		byNamespace: make(map[string]sets.Set[string]),
	}
}

func (ps *policyStore) updatePolicy(auth *security.Authorization) error {
	if auth == nil {
		return nil
	}

	authPolicy := authPolicy{
		auth,
	}
	key := authPolicy.Key()

	var ns string
	switch authPolicy.GetScope() {
	case security.Scope_GLOBAL:
		ns = ""
	case security.Scope_NAMESPACE:
		ns = authPolicy.GetNamespace()
	case security.Scope_WORKLOAD_SELECTOR:
		// do nothing
	default:
		return fmt.Errorf("invalid scope %v of authorization policy", authPolicy.GetScope())
	}

	ps.rwLock.Lock()
	defer ps.rwLock.Unlock()

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

	var ns string
	switch authPolicy.Scope {
	case security.Scope_GLOBAL:
		ns = ""
	case security.Scope_NAMESPACE:
		ns = authPolicy.GetNamespace()
	}

	// remove authPolicy key from byNamespace
	if s, ok := ps.byNamespace[ns]; ok {
		s.Delete(policyKey)
		if s.IsEmpty() {
			delete(ps.byNamespace, ns)
		}
	}

	// remove authPolicy from byKey
	delete(ps.byKey, policyKey)
}

// getByNamesapce returns a copied set of policy name in namespace, or an empty set if namespace not exists
func (ps *policyStore) getByNamesapce(namespace string) sets.Set[string] {
	ps.rwLock.RLock()
	defer ps.rwLock.RUnlock()

	if s, ok := ps.byNamespace[namespace]; ok {
		return s.Copy()
	}
	return sets.New[string]()
}

type authPolicy struct {
	*security.Authorization
}

func (ap *authPolicy) Key() string {
	return fmt.Sprintf("%s/%s", ap.GetNamespace(), ap.GetName())
}
