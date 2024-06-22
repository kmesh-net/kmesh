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
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/assert"
	"istio.io/istio/pkg/util/sets"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/api/v2/workloadapi/security"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
)

const (
	GLOBAL_NAMESPACE = ""
	ALLOW_AUTH       = "allow-sleep-to-kmesh"
	DENY_AUTH        = "deny-sleep-to-kmesh"
	ALLOW_POLICY     = GLOBAL_NAMESPACE + "/" + ALLOW_AUTH
	DENY_POLICY      = GLOBAL_NAMESPACE + "/" + DENY_AUTH
)

var (
	policy1 = &security.Authorization{
		Name:      "_name",
		Namespace: "_namespace",
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 1},
										Length:  32,
									},
									{
										Address: []byte{192, 168, 122, 2},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy2_1 = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 0},
										Length:  24,
									},
									{
										Address: []byte{192, 168, 123, 0},
										Length:  24,
									},
								},
								NotDestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 124, 0},
										Length:  24,
									},
									{
										Address: []byte{192, 168, 125, 0},
										Length:  24,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy2_2 = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 0},
										Length:  24,
									},
									{
										Address: []byte{192, 168, 124, 0},
										Length:  24,
									},
								},
								NotDestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 0},
										Length:  24,
									},
									{
										Address: []byte{192, 168, 125, 0},
										Length:  24,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy2_3_deny = &security.Authorization{
		Name:      DENY_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_DENY,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								NotDestinationIps: []*security.Address{
									{
										Address: []byte{192, 167, 0, 0},
										Length:  16,
									},
									{
										Address: []byte{192, 169, 0, 0},
										Length:  16,
									},
								},
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 0, 0},
										Length:  16,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy2_3_allow = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 0, 0},
										Length:  16,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy2_4 = &security.Authorization{
		Name:      DENY_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_DENY,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 3},
										Length:  32,
									},
									{
										Address: net.ParseIP("fd80::2"),
										Length:  128,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy3_1 = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								SourceIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 10},
										Length:  32,
									},
									{
										Address: []byte{192, 168, 122, 4},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy3_2 = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								SourceIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 11},
										Length:  32,
									},
									{
										Address: []byte{192, 168, 122, 12},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy3_3_deny = &security.Authorization{
		Name:      DENY_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_DENY,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								NotDestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 0},
										Length:  24,
									},
									{
										Address: []byte{192, 168, 123, 0},
										Length:  24,
									},
								},
								NotSourceIps: []*security.Address{
									{
										Address: []byte{192, 168, 124, 0},
										Length:  24,
									},
									{
										Address: []byte{192, 168, 125, 0},
										Length:  24,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy3_3_allow = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 0},
										Length:  24,
									},
									{
										Address: []byte{192, 168, 123, 0},
										Length:  24,
									},
								},
								SourceIps: []*security.Address{
									{
										Address: []byte{192, 168, 124, 0},
										Length:  24,
									},
									{
										Address: []byte{192, 168, 125, 0},
										Length:  24,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy3_4 = &security.Authorization{
		Name:      DENY_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_DENY,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								SourceIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 11},
										Length:  32,
									},
									{
										Address: []byte{192, 168, 122, 12},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy4_1 = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationPorts: []uint32{8888, 8889},
							},
						},
					},
				},
			},
		},
	}

	policy4_2 = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationPorts: []uint32{8889, 8890},
							},
						},
					},
				},
			},
		},
	}

	policy4_3_deny = &security.Authorization{
		Name:      DENY_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_DENY,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								NotDestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 3},
										Length:  32,
									},
									{
										Address: []byte{192, 168, 122, 4},
										Length:  32,
									},
								},
								NotDestinationPorts: []uint32{8888, 8889},
							},
						},
					},
				},
			},
		},
	}

	policy4_3_allow = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 3},
										Length:  32,
									},
									{
										Address: []byte{192, 168, 122, 4},
										Length:  32,
									},
								},
								DestinationPorts: []uint32{8888, 8889},
							},
						},
					},
				},
			},
		},
	}

	policy4_4 = &security.Authorization{
		Name:      DENY_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_DENY,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationPorts: []uint32{8889, 8890},
							},
						},
					},
				},
			},
		},
	}

	policy5_1 = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								Principals: []*security.StringMatch{
									{
										MatchType: &security.StringMatch_Exact{
											Exact: "cluster.local/ns//sa/sleep",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy5_2 = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								Principals: []*security.StringMatch{
									{
										MatchType: &security.StringMatch_Prefix{
											Prefix: "k8s.io",
										},
									},
									{
										MatchType: &security.StringMatch_Suffix{
											Suffix: "notsleep",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy5_3_deny = &security.Authorization{
		Name:      DENY_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_DENY,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								NotDestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 3},
										Length:  32,
									},
									{
										Address: []byte{192, 168, 122, 4},
										Length:  32,
									},
								},
								NotPrincipals: []*security.StringMatch{
									{
										MatchType: &security.StringMatch_Suffix{
											Suffix: "sleep",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy5_3_allow = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 3},
										Length:  32,
									},
									{
										Address: []byte{192, 168, 122, 4},
										Length:  32,
									},
								},
								Principals: []*security.StringMatch{
									{
										MatchType: &security.StringMatch_Suffix{
											Suffix: "sleep",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy5_4 = &security.Authorization{
		Name:      DENY_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_DENY,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								Principals: []*security.StringMatch{
									{
										MatchType: &security.StringMatch_Exact{
											Exact: "cluster.local/ns//sa/notsleep",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy6_1 = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								Namespaces: []*security.StringMatch{
									{
										MatchType: &security.StringMatch_Exact{
											Exact: GLOBAL_NAMESPACE,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy6_2 = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								Namespaces: []*security.StringMatch{
									{
										MatchType: &security.StringMatch_Exact{
											Exact: "k8s-system",
										},
									},
									{
										MatchType: &security.StringMatch_Exact{
											Exact: "kube-system",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy6_3_deny = &security.Authorization{
		Name:      DENY_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_DENY,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								NotDestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 3},
										Length:  32,
									},
									{
										Address: []byte{192, 168, 122, 4},
										Length:  32,
									},
								},
								NotNamespaces: []*security.StringMatch{
									{
										MatchType: &security.StringMatch_Exact{
											Exact: GLOBAL_NAMESPACE,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy6_3_allow = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 3},
										Length:  32,
									},
									{
										Address: []byte{192, 168, 122, 4},
										Length:  32,
									},
								},
								Namespaces: []*security.StringMatch{
									{
										MatchType: &security.StringMatch_Exact{
											Exact: GLOBAL_NAMESPACE,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy6_4 = &security.Authorization{
		Name:      DENY_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_DENY,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								Namespaces: []*security.StringMatch{
									{
										MatchType: &security.StringMatch_Exact{
											Exact: "k8s-system",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy7_1 = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 2},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								SourceIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 3},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy7_2 = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 3},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								SourceIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 4},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy7_3 = &security.Authorization{
		Name:      DENY_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_DENY,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								NotDestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 2},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								NotSourceIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 3},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy7_4 = &security.Authorization{
		Name:      DENY_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_DENY,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 3},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								SourceIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 4},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy8_1 = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								NotDestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 2},
										Length:  32,
									},
								},
							},
						},
					},
					{
						Matches: []*security.Match{
							{
								SourceIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 3},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy8_2 = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 2},
										Length:  32,
									},
								},
							},
						},
					},
					{
						Matches: []*security.Match{
							{
								SourceIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 3},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy8_3 = &security.Authorization{
		Name:      DENY_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_DENY,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								NotDestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 2},
										Length:  32,
									},
								},
							},
						},
					},
					{
						Matches: []*security.Match{
							{
								NotSourceIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 3},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy8_4 = &security.Authorization{
		Name:      DENY_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_DENY,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 2},
										Length:  32,
									},
								},
							},
						},
					},
					{
						Matches: []*security.Match{
							{
								SourceIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 3},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy9_1 = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 2},
										Length:  32,
									},
								},
							},
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 3},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy9_2 = &security.Authorization{
		Name:      ALLOW_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 3},
										Length:  32,
									},
								},
							},
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 4},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy9_3 = &security.Authorization{
		Name:      DENY_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_DENY,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								NotDestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 2},
										Length:  32,
									},
								},
							},
							{
								NotDestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 3},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	policy9_4 = &security.Authorization{
		Name:      DENY_AUTH,
		Namespace: GLOBAL_NAMESPACE,
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_DENY,
		Rules: []*security.Rule{
			{
				Clauses: []*security.Clause{
					{
						Matches: []*security.Match{
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 3},
										Length:  32,
									},
								},
							},
							{
								DestinationIps: []*security.Address{
									{
										Address: []byte{192, 168, 122, 4},
										Length:  32,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	byNamespaceAllow = map[string]sets.Set[string]{GLOBAL_NAMESPACE: sets.New(ALLOW_POLICY)}

	byNamespaceDeny = map[string]sets.Set[string]{GLOBAL_NAMESPACE: sets.New(DENY_POLICY)}

	byNamespaceAllowDeny = map[string]sets.Set[string]{GLOBAL_NAMESPACE: sets.New(ALLOW_POLICY, DENY_POLICY)}

	emptyBPFContext = make([]byte, 15)
)

func TestRbac_doRbac(t *testing.T) {
	type fields struct {
		policyStore *policyStore
	}
	type args struct {
		conn     *rbacConnection
		workload *workloadapi.Workload
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			"1. No policy for workload, allow",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{"_namespace/_name": policy1},
					byNamespace: map[string]sets.Set[string]{"_namesapce": sets.New("_namespace/_name")},
				},
			},
			args{
				conn: &rbacConnection{
					srcIdentity: Identity{
						trustDomain:    "cluster.local",
						namespace:      GLOBAL_NAMESPACE,
						serviceAccount: "sleep",
					},
					srcIp:   []byte{192, 168, 122, 3},
					dstIp:   []byte{192, 168, 122, 4},
					dstPort: 8888,
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{
						{192, 168, 122, 4},
					},
				},
			},
			true,
		},

		{
			"2-1. Destination IP allow match, allow",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{ALLOW_POLICY: policy2_1},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				conn: &rbacConnection{dstIp: []byte{192, 168, 122, 2}},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}},
			true,
		},
		{
			"2-2. Destination IP allow mismatch, deny",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{ALLOW_POLICY: policy2_2},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				conn: &rbacConnection{dstIp: []byte{192, 168, 122, 2}},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}},
			false,
		},
		{
			"2-3. Destination IP deny match, deny",
			fields{
				&policyStore{
					byKey: map[string]*security.Authorization{
						DENY_POLICY:  policy2_3_deny,
						ALLOW_POLICY: policy2_3_allow,
					},
					byNamespace: byNamespaceAllowDeny,
				},
			},
			args{
				conn: &rbacConnection{dstIp: []byte{192, 168, 122, 2}},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}},
			false,
		},
		{
			"2-4. Destination IP deny mismatch, allow",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{DENY_POLICY: policy2_4},
					byNamespace: byNamespaceDeny,
				},
			},
			args{
				conn: &rbacConnection{dstIp: []byte{192, 168, 122, 2}},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}},
			true,
		},

		{
			"3-1. Source IP allow match, allow",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{ALLOW_POLICY: policy3_1},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				conn: &rbacConnection{
					srcIp: []byte{192, 168, 122, 10},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}},
			true,
		},
		{
			"3-2. Source IP allow mismatch, deny",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{ALLOW_POLICY: policy3_2},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				conn: &rbacConnection{
					srcIp: []byte{192, 168, 122, 10},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}}, false,
		},
		{
			"3-3. Source IP deny match, deny",
			fields{
				&policyStore{
					byKey: map[string]*security.Authorization{
						DENY_POLICY:  policy3_3_deny,
						ALLOW_POLICY: policy3_3_allow,
					},
					byNamespace: byNamespaceAllowDeny,
				},
			},
			args{
				conn: &rbacConnection{
					srcIp: []byte{192, 168, 122, 10},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}}, false,
		},
		{
			"3-4. Source IP deny mismatch, allow",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{DENY_POLICY: policy3_4},
					byNamespace: byNamespaceDeny,
				},
			},
			args{
				conn: &rbacConnection{
					srcIp: []byte{192, 168, 122, 10},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}}, true,
		},

		{
			"4-1. Destination port allow match, allow",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{ALLOW_POLICY: policy4_1},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				conn: &rbacConnection{
					dstIp:   []byte{192, 168, 122, 2},
					dstPort: 8888,
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}},
			true,
		},
		{
			"4-2. Destination port allow mismatch, deny",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{ALLOW_POLICY: policy4_2},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				conn: &rbacConnection{
					dstIp:   []byte{192, 168, 122, 2},
					dstPort: 8888,
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}},
			false,
		},
		{
			"4-3. Destination port deny match, deny",
			fields{
				&policyStore{
					byKey: map[string]*security.Authorization{
						DENY_POLICY:  policy4_3_deny,
						ALLOW_POLICY: policy4_3_allow,
					},
					byNamespace: byNamespaceAllowDeny,
				},
			},
			args{
				conn: &rbacConnection{
					dstIp:   []byte{192, 168, 122, 2},
					dstPort: 8888,
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}},
			false,
		},
		{
			"4-4. Destination port deny mismatch, allow",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{DENY_POLICY: policy4_4},
					byNamespace: byNamespaceDeny,
				},
			},
			args{
				conn: &rbacConnection{
					dstIp:   []byte{192, 168, 122, 2},
					dstPort: 8888,
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}},
			true,
		},

		{
			"5-1. Principal allow match, allow",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{ALLOW_POLICY: policy5_1},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				conn: &rbacConnection{
					srcIdentity: Identity{
						trustDomain:    "cluster.local",
						namespace:      GLOBAL_NAMESPACE,
						serviceAccount: "sleep",
					},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}},
			true,
		},
		{
			"5-2. Principal allow mismatch, deny",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{ALLOW_POLICY: policy5_2},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				conn: &rbacConnection{
					srcIdentity: Identity{
						trustDomain:    "cluster.local",
						namespace:      GLOBAL_NAMESPACE,
						serviceAccount: "sleep",
					},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}},
			false,
		},
		{
			"5-3. Principal deny match, deny",
			fields{
				&policyStore{
					byKey: map[string]*security.Authorization{
						DENY_POLICY:  policy5_3_deny,
						ALLOW_POLICY: policy5_3_allow,
					},
					byNamespace: byNamespaceAllowDeny,
				},
			},
			args{
				conn: &rbacConnection{
					srcIdentity: Identity{
						trustDomain:    "cluster.local",
						namespace:      GLOBAL_NAMESPACE,
						serviceAccount: "sleep",
					},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}},
			false,
		},
		{
			"5-4. Principal deny mismatch, allow",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{DENY_POLICY: policy5_4},
					byNamespace: byNamespaceDeny,
				},
			},
			args{
				conn: &rbacConnection{
					srcIdentity: Identity{
						trustDomain:    "cluster.local",
						namespace:      GLOBAL_NAMESPACE,
						serviceAccount: "sleep",
					},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}},
			true,
		},

		{
			"6-1. Namespace allow match, allow",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{ALLOW_POLICY: policy6_1},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				conn: &rbacConnection{
					srcIdentity: Identity{
						namespace: GLOBAL_NAMESPACE,
					},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}},
			true,
		},
		{
			"6-2. Namespace allow mismatch, deny",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{ALLOW_POLICY: policy6_2},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				conn: &rbacConnection{
					srcIdentity: Identity{
						namespace: GLOBAL_NAMESPACE,
					},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}}, false,
		},
		{
			"6-3. Namespace deny match, deny",
			fields{
				&policyStore{
					byKey: map[string]*security.Authorization{
						DENY_POLICY:  policy6_3_deny,
						ALLOW_POLICY: policy6_3_allow,
					},
					byNamespace: byNamespaceAllowDeny,
				},
			},
			args{
				conn: &rbacConnection{
					srcIdentity: Identity{
						namespace: GLOBAL_NAMESPACE,
					},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}},
			false,
		},
		{
			"6-4. Namespace deny mismatch, allow",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{DENY_POLICY: policy6_4},
					byNamespace: byNamespaceDeny,
				},
			},
			args{
				conn: &rbacConnection{
					srcIdentity: Identity{
						namespace: GLOBAL_NAMESPACE,
					},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}},
			true,
		},

		{
			"7-1. Test rules OR-ed allow, 1 rule matches, allow",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{ALLOW_POLICY: policy7_1},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				conn: &rbacConnection{
					srcIp: []byte{192, 168, 122, 4},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				}},
			true,
		},
		{
			"7-2. Test rules OR-ed allow, no rule matches, deny",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{ALLOW_POLICY: policy7_2},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				conn: &rbacConnection{
					srcIp: []byte{192, 168, 122, 5},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				},
			},
			false,
		},
		{
			"7-3. Test rules OR-ed deny, 1 rule matches, deny",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{DENY_POLICY: policy7_3},
					byNamespace: byNamespaceDeny,
				},
			},
			args{
				conn: &rbacConnection{
					srcIp: []byte{192, 168, 122, 4},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				},
			},
			false,
		},
		{
			"7-4. Test rules OR-ed deny, no rule matches, allow",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{DENY_POLICY: policy7_4},
					byNamespace: byNamespaceDeny,
				},
			},
			args{
				conn: &rbacConnection{
					srcIp: []byte{192, 168, 122, 5},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				},
			},
			true,
		},

		{
			"8-1. Test clauses AND-ed allow, 1 clause mismatches, deny",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{ALLOW_POLICY: policy8_1},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				conn: &rbacConnection{
					srcIp: []byte{192, 168, 122, 4},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				},
			},
			false,
		},
		{
			"8-2. Test clauses AND-ed allow, all clauses match, allow",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{ALLOW_POLICY: policy8_2},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				conn: &rbacConnection{
					srcIp: []byte{192, 168, 122, 3},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				},
			},
			true,
		},
		{
			"8-3. Test clauses AND-ed deny, 1 clause mismatch, allow",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{DENY_POLICY: policy8_3},
					byNamespace: byNamespaceDeny,
				},
			},
			args{
				conn: &rbacConnection{
					srcIp: []byte{192, 168, 122, 4},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				},
			},
			true,
		},
		{
			"8-4. Test clauses AND-ed deny, all clauses match, deny",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{DENY_POLICY: policy8_4},
					byNamespace: byNamespaceDeny,
				},
			},
			args{
				conn: &rbacConnection{
					srcIp: []byte{192, 168, 122, 3},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				},
			},
			false,
		},

		{
			"9-1. Test matches OR-ed allow, 1 match matches, allow",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{ALLOW_POLICY: policy9_1},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				conn: &rbacConnection{
					srcIp: []byte{192, 168, 122, 4},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				},
			},
			true,
		},
		{
			"9-2. Test matches OR-ed allow, no match matches, deny",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{ALLOW_POLICY: policy9_2},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				conn: &rbacConnection{
					srcIp: []byte{192, 168, 122, 5},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				},
			},
			false,
		},
		{
			"9-3. Test matches OR-ed deny, 1 match matches, deny",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{DENY_POLICY: policy9_3},
					byNamespace: byNamespaceDeny,
				},
			},
			args{
				conn: &rbacConnection{
					srcIp: []byte{192, 168, 122, 4},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				},
			},
			false,
		},
		{
			"9-4. Test matches OR-ed deny, no match matches, allow",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{DENY_POLICY: policy9_4},
					byNamespace: byNamespaceDeny,
				},
			},
			args{
				conn: &rbacConnection{
					srcIp: []byte{192, 168, 122, 5},
					dstIp: []byte{192, 168, 122, 2},
				},
				workload: &workloadapi.Workload{
					Addresses: [][]byte{{192, 168, 122, 2}},
				},
			},
			true,
		},
		{
			"9-4-1. no workload found, deny",
			fields{
				&policyStore{
					byKey:       map[string]*security.Authorization{DENY_POLICY: policy9_4},
					byNamespace: byNamespaceDeny,
				},
			},
			args{
				conn: &rbacConnection{
					srcIp: []byte{192, 168, 122, 5},
					dstIp: []byte{192, 168, 122, 2},
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workloadCache := cache.NewWorkloadCache()
			workloadCache.AddWorkload(tt.args.workload)
			rbac := &Rbac{
				policyStore:   tt.fields.policyStore,
				workloadCache: workloadCache,
			}
			if got := rbac.doRbac(tt.args.conn); got != tt.want {
				t.Errorf("Rbac.DoRbac() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_handleAuthorizationTypeResponse(t *testing.T) {
	policy1 := &security.Authorization{
		Name:      "p1",
		Namespace: "test",
		Scope:     security.Scope_WORKLOAD_SELECTOR,
		Action:    security.Action_ALLOW,
		Rules:     []*security.Rule{},
	}

	policy2 := &security.Authorization{
		Name:      "p2",
		Namespace: "test",
		Scope:     security.Scope_NAMESPACE,
		Action:    security.Action_ALLOW,
		Rules:     []*security.Rule{},
	}

	rbac := NewRbac(nil) // Initialize your rbac object here

	err := rbac.UpdatePolicy(policy1)
	assert.NoError(t, err)

	err = rbac.UpdatePolicy(policy2)
	assert.NoError(t, err)

	rbac.RemovePolicy(policy1.ResourceName())

	if !rbac.policyStore.byNamespace["test"].Contains(policy2.ResourceName()) {
		t.Errorf("policy2 should still be in the policy store")
	}
}

func genRingbuf(t *testing.T, msgType uint32, msgSize int, flags int32) (*ebpf.Program, *ebpf.Map, error) {
	rbMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "map_of_tuple",
		Type:       ebpf.RingBuf,
		MaxEntries: 4096,
	})
	if err != nil {
		t.Error("Create rbMap failed, err: ", err)
		return nil, nil, err
	}

	var msgData []uint64
	switch msgType {
	case MSG_TYPE_IPV4:
		msgData = []uint64{
			0x00000000C0A87801, // msgType = 0, srcIP = 192.168.120.1
			0xC0A87A03C26C1F90, // dstIP = 192.168.122.3, srcPort = 27842, dstPort = 8080
			// filled data
			0,
			0,
			0,
		}
	case MSG_TYPE_IPV6:
		msgData = []uint64{
			0x0100000000000001, // msgType = 1, srcIP = fd80::1
			0,
			0xFD80000000000002,
			0,
			0xFD800000C26C1F90, // dstIP = fd80::2, srcPort = 27842, dstPort = 8080
		}
	default:
		t.Fatal("Invalid msgType")
	}

	insns := asm.Instructions{
		asm.Mov.Reg(asm.R9, asm.R1),
	}

	bufDwords := msgSize / 8
	for i := 0; i < bufDwords; i++ {
		insns = append(insns,
			asm.LoadImm(asm.R0, int64(msgData[i]), asm.DWord),
			asm.StoreMem(asm.RFP, int16(i+1)*-8, asm.R0, asm.DWord),
		)
	}

	insns = append(insns,
		asm.LoadMapPtr(asm.R1, rbMap.FD()),
		asm.Mov.Imm(asm.R2, int32(msgSize)),
		asm.Mov.Imm(asm.R3, int32(0)),
		asm.FnRingbufReserve.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.Mov.Reg(asm.R5, asm.R0),
	)
	for i := 0; i < msgSize; i++ {
		insns = append(insns,
			asm.LoadMem(asm.R4, asm.RFP, int16(i+1)*-1, asm.Byte),
			asm.StoreMem(asm.R5, int16(i), asm.R4, asm.Byte),
		)
	}
	insns = append(insns,
		asm.Mov.Reg(asm.R1, asm.R5),
		asm.Mov.Imm(asm.R2, flags),
		asm.FnRingbufSubmit.Call(),
	)

	insns = append(insns,
		asm.Mov.Imm(asm.R0, int32(0)).WithSymbol("exit"),
		asm.Return(),
	)

	rbProg, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		License:      "Dual BSD/GPL",
		Type:         ebpf.XDP,
		Instructions: insns,
	})
	if err != nil {
		t.Error("Create rbProg failed, err: ", err)
		rbMap.Close()
		return nil, nil, err
	}

	return rbProg, rbMap, nil
}

func prepareMaps(t *testing.T, msgType uint32) (mapOfTuple, mapOfAuth *ebpf.Map) {
	sockOpsProg, mapOfTuple, err := genRingbuf(t, msgType, MSG_LEN, 0)
	if err != nil {
		t.Fatal("Create mapOfTuple failed, err: ", err)
	}
	ret, _, err := sockOpsProg.Test(emptyBPFContext)
	if err != nil {
		t.Fatal(err)
	}
	if errno := syscall.Errno(-int32(ret)); errno != 0 {
		t.Fatal("Expected 0 as return value, got", errno)
	}

	mapOfAuth, err = ebpf.NewMap(&ebpf.MapSpec{
		Name:       "map_of_auth",
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(bpfSockTupleV6{})),
		ValueSize:  uint32(unsafe.Sizeof(uint32(0))),
		MaxEntries: 4096,
	})
	if err != nil {
		t.Fatal("Create mapOfAuth failed, err: ", err)
	}

	sockOpsProg.Close()
	return
}

func genIPv6LookupKey() []byte {
	key := []byte{0, 0, 0, 0x01}
	key = append(key, append(make([]byte, 8), 0xFD, 0x80)...)
	key = append(key, append(make([]byte, 5), 0x02)...)
	key = append(key, append(make([]byte, 8), 0xFD, 0x80, 0, 0, 0xC2, 0x6C, 0x1F, 0x90)...)
	return key
}

func TestRbac_Run(t *testing.T) {
	type args struct {
		msgType   uint32
		lookupKey []byte
	}

	// Common variables in test func
	policyStore := &policyStore{
		byKey:       map[string]*security.Authorization{DENY_POLICY: policy2_4},
		byNamespace: byNamespaceDeny,
	}

	workloadCache := cache.NewWorkloadCache()
	workloadCache.AddWorkload(&workloadapi.Workload{
		Name: "ut-workload",
		Uid:  "123456",
		Addresses: [][]byte{
			{192, 168, 120, 1},
			net.ParseIP("fd80::1"),
		},
		AuthorizationPolicies: []string{DENY_AUTH},
	})

	tests := []struct {
		name      string
		args      args
		wantFound bool
	}{
		{
			"1. IPv4: Deny, records found in map_of_auth",
			args{
				msgType: MSG_TYPE_IPV4,
				lookupKey: append([]byte{0xC0, 0xA8, 0x78, 0x01, 0xC0, 0xA8, 0x7A, 0x03, 0xC2, 0x6C, 0x1F, 0x90},
					make([]byte, TUPLE_LEN-IPV4_TUPLE_LENGTH)...),
			},
			true,
		},
		{
			"2. IPv6: Deny, records found in map_of_auth",
			args{
				msgType:   MSG_TYPE_IPV6,
				lookupKey: genIPv6LookupKey(),
			},
			true,
		},
	}
	for _, tt := range tests {
		ctx, cancelFunc := context.WithCancel(context.Background())
		mapOfTuple, mapOfAuth := prepareMaps(t, tt.args.msgType)
		r := &Rbac{
			policyStore:   policyStore,
			workloadCache: workloadCache,
			notifyFunc: func(mapOfAuth *ebpf.Map, msgType uint32, key []byte) error {
				defer cancelFunc()
				if err := xdpNotifyConnRst(mapOfAuth, msgType, key); err != nil {
					return err
				}
				return nil
			},
		}

		// Perform auth runner and wait for return
		r.Run(ctx, mapOfTuple, mapOfAuth)

		// Do lookup
		var val uint32
		err := mapOfAuth.Lookup(tt.args.lookupKey, &val)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatal("Do lookup failed, err: ", err)
		}

		// Judge results
		found := val == 1
		if found != tt.wantFound {
			t.Errorf("want %v, but got %v", tt.wantFound, found)
		}

		// Close maps
		mapOfTuple.Close()
		mapOfAuth.Close()
	}
}
