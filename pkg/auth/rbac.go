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

 * Author: supercharge-xsy
 * Create: 2024-01-22
 */

package auth

import (
	security "kmesh.net/kmesh/api/v2/workloadapi/security"
)

// type Rbac struct {
// 	policies PolicyStore
// }

type PolicyStore struct {
	// policies maintains a mapping of ns/name to policy
	by_key map[string]*AuthPolicy

	// policies_by_namespace maintains a mapping of namespace (or "" for global) to policy names
	by_namespace map[string][]string
}

func NewPolicystore() *PolicyStore {
	return &PolicyStore{
		by_key:       make(map[string]*AuthPolicy),
		by_namespace: make(map[string][]string),
	}

}

type AuthPolicy struct {
	*security.Authorization
}

func (a *AuthPolicy) to_key() string {
	return a.GetName() + a.GetNamespace()
}

func (ps *PolicyStore) UpdatePolicy(security_auth *security.Authorization) error {
	authPolicy := &AuthPolicy{
		security_auth,
	}
	key := authPolicy.to_key()
	switch authPolicy.Scope {
	case security.Scope_GLOBAL:
		ps.by_namespace[""] = append(ps.by_namespace[""], key)
	case security.Scope_NAMESPACE:
		ps.by_namespace[authPolicy.Namespace] = append(ps.by_namespace[authPolicy.Namespace], key)
	case security.Scope_WORKLOAD_SELECTOR:
		ps.by_key[key] = authPolicy
	default:
		break
	}

	return nil
}

func (ps *PolicyStore) RemovePolicy(policyKey string) error {
	authPolicy := ps.by_key[policyKey]

	// remove authpolicy name from by_namespace
	switch authPolicy.Scope {
	case security.Scope_GLOBAL:
		RemoveStrFromSlice(ps.by_namespace[""], policyKey)
	case security.Scope_NAMESPACE:
		RemoveStrFromSlice(ps.by_namespace[authPolicy.Namespace], policyKey)
	default:
		break
	}
	// remove authPolicy entry from by_key map
	delete(ps.by_key, policyKey)

	return nil

}

// todo move to utils.go
func RemoveStrFromSlice(slice []string, obj string) []string {
	var newSlice []string
	for _, item := range slice {
		if item != obj {
			newSlice = append(newSlice, item)
		}
	}
	return newSlice
}
