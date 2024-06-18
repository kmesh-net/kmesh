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
	"testing"

	"kmesh.net/kmesh/api/v2/workloadapi/security"
)

func Test_policyStore_updatePolicy(t *testing.T) {
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

func Test_policyStore_removePolicy(t *testing.T) {
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
