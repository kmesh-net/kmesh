// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package model

import (
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	rbacpb "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	routepb "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
)

func principalAny() *rbacpb.Principal {
	return &rbacpb.Principal{
		Identifier: &rbacpb.Principal_Any{
			Any: true,
		},
	}
}

func principalOr(principals []*rbacpb.Principal) *rbacpb.Principal {
	return &rbacpb.Principal{
		Identifier: &rbacpb.Principal_OrIds{
			OrIds: &rbacpb.Principal_Set{
				Ids: principals,
			},
		},
	}
}

func principalAnd(principals []*rbacpb.Principal) *rbacpb.Principal {
	return &rbacpb.Principal{
		Identifier: &rbacpb.Principal_AndIds{
			AndIds: &rbacpb.Principal_Set{
				Ids: principals,
			},
		},
	}
}

func principalNot(principal *rbacpb.Principal) *rbacpb.Principal {
	return &rbacpb.Principal{
		Identifier: &rbacpb.Principal_NotId{
			NotId: principal,
		},
	}
}

func principalAuthenticated(name *matcher.StringMatcher, useAuthenticated bool) *rbacpb.Principal {
	if useAuthenticated {
		return &rbacpb.Principal{
			Identifier: &rbacpb.Principal_Authenticated_{
				Authenticated: &rbacpb.Principal_Authenticated{
					PrincipalName: name,
				},
			},
		}
	}
	return &rbacpb.Principal{
		Identifier: &rbacpb.Principal_FilterState{
			FilterState: &matcher.FilterStateMatcher{
				Key: "io.istio.peer_principal",
				Matcher: &matcher.FilterStateMatcher_StringMatch{
					StringMatch: name,
				},
			},
		},
	}
}

func principalDirectRemoteIP(cidr *core.CidrRange) *rbacpb.Principal {
	return &rbacpb.Principal{
		Identifier: &rbacpb.Principal_DirectRemoteIp{
			DirectRemoteIp: cidr,
		},
	}
}

func principalRemoteIP(cidr *core.CidrRange) *rbacpb.Principal {
	return &rbacpb.Principal{
		Identifier: &rbacpb.Principal_RemoteIp{
			RemoteIp: cidr,
		},
	}
}

func principalMetadata(metadata *matcher.MetadataMatcher) *rbacpb.Principal {
	return &rbacpb.Principal{
		Identifier: &rbacpb.Principal_Metadata{
			Metadata: metadata,
		},
	}
}

func principalHeader(header *routepb.HeaderMatcher) *rbacpb.Principal {
	return &rbacpb.Principal{
		Identifier: &rbacpb.Principal_Header{
			Header: header,
		},
	}
}
