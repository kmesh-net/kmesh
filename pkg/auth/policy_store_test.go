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
	"testing"

	"kmesh.net/kmesh/api/v2/workloadapi/security"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/utils/test"
)

func Test_policyStore_updatePolicy(t *testing.T) {
	config := options.BpfConfig{
		Mode:        constants.DualEngineMode,
		BpfFsPath:   "/sys/fs/bpf",
		Cgroup2Path: "/mnt/kmesh_cgroup2",
	}
	cleanup, _ := test.InitBpfMap(t, config)
	t.Cleanup(cleanup)

	type args struct {
		auth *security.Authorization
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"1-1. Test update global scope, success",
			args{
				&security.Authorization{
					Name:  "auth-name",
					Scope: security.Scope_GLOBAL,
				},
			},
			false,
		},
		{
			"1-2. Test update namespace scope, success",
			args{
				&security.Authorization{
					Name:      "auth-name",
					Namespace: "auth-namespace",
					Scope:     security.Scope_NAMESPACE,
				},
			},
			false,
		},
		{
			"1-3. Test update workload scope, success",
			args{
				&security.Authorization{
					Name:      "auth-name",
					Namespace: "auth-namespace",
					Scope:     security.Scope_WORKLOAD_SELECTOR,
				},
			},
			false,
		},
		{
			"2. Test update invalid scope, fail",
			args{
				&security.Authorization{
					Name:      "auth-name",
					Namespace: "auth-namespace",
					Scope:     3,
				},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps := newPolicyStore()
			if err := ps.updatePolicy(tt.args.auth); (err != nil) != tt.wantErr {
				t.Errorf("policyStore.updatePolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Test_policyStore_updatePolicy_scopeChange verifies that when an existing
// policy changes scope, the stale namespace/global index entry is removed so a
// policy is only discoverable through the index matching its current scope.
func Test_policyStore_updatePolicy_scopeChange(t *testing.T) {
	newAuth := func(scope security.Scope) *security.Authorization {
		return &security.Authorization{
			Name:      "auth-name",
			Namespace: "auth-namespace",
			Scope:     scope,
		}
	}

	tests := []struct {
		name string
		from security.Scope
		to   security.Scope
		// oldNs is the namespace index bucket that must no longer contain the
		// policy after the update; "" is the global bucket.
		oldNs string
		// newNs is the namespace index bucket that must contain the policy after
		// the update, or "-" when the policy should not be in any bucket.
		newNs string
	}{
		{"namespace to global", security.Scope_NAMESPACE, security.Scope_GLOBAL, "auth-namespace", ""},
		{"namespace to workload selector", security.Scope_NAMESPACE, security.Scope_WORKLOAD_SELECTOR, "auth-namespace", "-"},
		{"global to namespace", security.Scope_GLOBAL, security.Scope_NAMESPACE, "", "auth-namespace"},
		{"global to workload selector", security.Scope_GLOBAL, security.Scope_WORKLOAD_SELECTOR, "", "-"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps := newPolicyStore()
			initial := newAuth(tt.from)
			key := initial.ResourceName()
			if err := ps.updatePolicy(initial); err != nil {
				t.Fatalf("updatePolicy(initial) error = %v", err)
			}
			if err := ps.updatePolicy(newAuth(tt.to)); err != nil {
				t.Fatalf("updatePolicy(updated) error = %v", err)
			}

			// The stale bucket must not reference the policy anymore.
			if s, ok := ps.byNamespace[tt.oldNs]; ok && s.Contains(key) {
				t.Errorf("policy %q still present in stale namespace index bucket %q", key, tt.oldNs)
			}

			if tt.newNs == "-" {
				for ns, s := range ps.byNamespace {
					if s.Contains(key) {
						t.Errorf("policy %q should not be in any namespace index bucket, found in %q", key, ns)
					}
				}
			} else if s, ok := ps.byNamespace[tt.newNs]; !ok || !s.Contains(key) {
				t.Errorf("policy %q missing from expected namespace index bucket %q", key, tt.newNs)
			}

			// The policy must always remain resolvable by key.
			if _, ok := ps.byKey[key]; !ok {
				t.Errorf("policy %q missing from byKey after update", key)
			}
		})
	}
}

// Test_policyStore_updatePolicy_scopeChangeKeepsSiblings verifies that
// rescoping one policy does not evict other policies sharing the same
// namespace index bucket.
func Test_policyStore_updatePolicy_scopeChangeKeepsSiblings(t *testing.T) {
	ps := newPolicyStore()
	p1 := &security.Authorization{Name: "p1", Namespace: "ns1", Scope: security.Scope_NAMESPACE}
	p2 := &security.Authorization{Name: "p2", Namespace: "ns1", Scope: security.Scope_NAMESPACE}
	if err := ps.updatePolicy(p1); err != nil {
		t.Fatalf("updatePolicy(p1) error = %v", err)
	}
	if err := ps.updatePolicy(p2); err != nil {
		t.Fatalf("updatePolicy(p2) error = %v", err)
	}

	// Rescope p1 to global; p2 must stay in the ns1 bucket.
	if err := ps.updatePolicy(&security.Authorization{Name: "p1", Namespace: "ns1", Scope: security.Scope_GLOBAL}); err != nil {
		t.Fatalf("updatePolicy(p1 rescope) error = %v", err)
	}
	if s, ok := ps.byNamespace["ns1"]; !ok || !s.Contains(p2.ResourceName()) {
		t.Errorf("sibling policy %q should remain in namespace bucket ns1", p2.ResourceName())
	}
	if ps.byNamespace["ns1"].Contains(p1.ResourceName()) {
		t.Errorf("rescoped policy %q should no longer be in namespace bucket ns1", p1.ResourceName())
	}
}

func Test_policyStore_removePolicy(t *testing.T) {
	config := options.BpfConfig{
		Mode:        constants.DualEngineMode,
		BpfFsPath:   "/sys/fs/bpf",
		Cgroup2Path: "/mnt/kmesh_cgroup2",
	}
	cleanup, _ := test.InitBpfMap(t, config)
	t.Cleanup(cleanup)

	type args struct {
		policyKey string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			"1-1. Test delete global scope, success",
			args{policyKey: "/auth-name"},
		},
		{
			"1-2. Test delete namespace scope, success",
			args{policyKey: "ns-name/auth-name"},
		},
		{
			"1-3. Test delete workload scope, success",
			args{policyKey: "ns-name/auth-name"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps := newPolicyStore()
			ps.removePolicy(tt.args.policyKey)
		})
	}
}
