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

	"istio.io/istio/pkg/util/sets"

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
	policy1 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy2_1 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy2_2 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy2_3_deny = authPolicy{
		&security.Authorization{
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
		},
	}

	policy2_3_allow = authPolicy{
		&security.Authorization{
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
		},
	}

	policy2_4 = authPolicy{
		&security.Authorization{
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
			},
		},
	}

	policy3_1 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy3_2 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy3_3_deny = authPolicy{
		&security.Authorization{
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
		},
	}

	policy3_3_allow = authPolicy{
		&security.Authorization{
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
		},
	}

	policy3_4 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy4_1 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy4_2 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy4_3_deny = authPolicy{
		&security.Authorization{
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
		},
	}

	policy4_3_allow = authPolicy{
		&security.Authorization{
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
		},
	}

	policy4_4 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy5_1 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy5_2 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy5_3_deny = authPolicy{
		&security.Authorization{
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
		},
	}

	policy5_3_allow = authPolicy{
		&security.Authorization{
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
		},
	}

	policy5_4 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy6_1 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy6_2 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy6_3_deny = authPolicy{
		&security.Authorization{
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
		},
	}

	policy6_3_allow = authPolicy{
		&security.Authorization{
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
		},
	}

	policy6_4 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy7_1 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy7_2 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy7_3 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy7_4 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy8_1 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy8_2 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy8_3 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy8_4 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy9_1 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy9_2 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy9_3 = authPolicy{
		&security.Authorization{
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
		},
	}

	policy9_4 = authPolicy{
		&security.Authorization{
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
		},
	}

	byNamespaceAllow = map[string]sets.Set[string]{GLOBAL_NAMESPACE: sets.New(ALLOW_POLICY)}

	byNamespaceDeny = map[string]sets.Set[string]{GLOBAL_NAMESPACE: sets.New(DENY_POLICY)}

	byNamespaceAllowDeny = map[string]sets.Set[string]{GLOBAL_NAMESPACE: sets.New(ALLOW_POLICY, DENY_POLICY)}
)

func TestRbac_doRbac(t *testing.T) {
	type fields struct {
		policyStore *policyStore
	}
	type args struct {
		conn *rbacConnection
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
					byKey:       map[string]authPolicy{"_namespace/_name": policy1},
					byNamespace: map[string]sets.Set[string]{"_namesapce": sets.New("_namespace/_name")},
				},
			},
			args{
				&rbacConnection{
					srcIdentity: Identity{
						trustDomain:    "cluster.local",
						namespace:      GLOBAL_NAMESPACE,
						serviceAccount: "sleep",
					},
					srcIp:   []byte{192, 168, 122, 3},
					dstIp:   []byte{192, 168, 122, 4},
					dstPort: 8888,
				},
			},
			true,
		},

		{
			"2-1. Destination IP allow match, allow",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{ALLOW_POLICY: policy2_1},
					byNamespace: byNamespaceAllow,
				},
			},
			args{&rbacConnection{dstIp: []byte{192, 168, 122, 2}}},
			true,
		},
		{
			"2-2. Destination IP allow mismatch, deny",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{ALLOW_POLICY: policy2_2},
					byNamespace: byNamespaceAllow,
				},
			},
			args{&rbacConnection{dstIp: []byte{192, 168, 122, 2}}},
			false,
		},
		{
			"2-3. Destination IP deny match, deny",
			fields{
				&policyStore{
					byKey: map[string]authPolicy{
						DENY_POLICY:  policy2_3_deny,
						ALLOW_POLICY: policy2_3_allow,
					},
					byNamespace: byNamespaceAllowDeny,
				},
			},
			args{&rbacConnection{dstIp: []byte{192, 168, 122, 2}}},
			false,
		},
		{
			"2-4. Destination IP deny mismatch, allow",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{DENY_POLICY: policy2_4},
					byNamespace: byNamespaceDeny,
				},
			},
			args{&rbacConnection{dstIp: []byte{192, 168, 122, 2}}},
			true,
		},

		{
			"3-1. Source IP allow match, allow",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{ALLOW_POLICY: policy3_1},
					byNamespace: byNamespaceAllow,
				},
			},
			args{&rbacConnection{srcIp: []byte{192, 168, 122, 10}}},
			true,
		},
		{
			"3-2. Source IP allow mismatch, deny",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{ALLOW_POLICY: policy3_2},
					byNamespace: byNamespaceAllow,
				},
			},
			args{&rbacConnection{srcIp: []byte{192, 168, 122, 10}}},
			false,
		},
		{
			"3-3. Source IP deny match, deny",
			fields{
				&policyStore{
					byKey: map[string]authPolicy{
						DENY_POLICY:  policy3_3_deny,
						ALLOW_POLICY: policy3_3_allow,
					},
					byNamespace: byNamespaceAllowDeny,
				},
			},
			args{&rbacConnection{srcIp: []byte{192, 168, 122, 10}}},
			false,
		},
		{
			"3-4. Source IP deny mismatch, allow",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{DENY_POLICY: policy3_4},
					byNamespace: byNamespaceDeny,
				},
			},
			args{&rbacConnection{srcIp: []byte{192, 168, 122, 10}}},
			true,
		},

		{
			"4-1. Destination port allow match, allow",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{ALLOW_POLICY: policy4_1},
					byNamespace: byNamespaceAllow,
				},
			},
			args{&rbacConnection{dstPort: 8888}},
			true,
		},
		{
			"4-2. Destination port allow mismatch, deny",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{ALLOW_POLICY: policy4_2},
					byNamespace: byNamespaceAllow,
				},
			},
			args{&rbacConnection{dstPort: 8888}},
			false,
		},
		{
			"4-3. Destination port deny match, deny",
			fields{
				&policyStore{
					byKey: map[string]authPolicy{
						DENY_POLICY:  policy4_3_deny,
						ALLOW_POLICY: policy4_3_allow,
					},
					byNamespace: byNamespaceAllowDeny,
				},
			},
			args{&rbacConnection{dstPort: 8888}},
			false,
		},
		{
			"4-4. Destination port deny mismatch, allow",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{DENY_POLICY: policy4_4},
					byNamespace: byNamespaceDeny,
				},
			},
			args{&rbacConnection{dstPort: 8888}},
			true,
		},

		{
			"5-1. Principal allow match, allow",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{ALLOW_POLICY: policy5_1},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				&rbacConnection{
					srcIdentity: Identity{
						trustDomain:    "cluster.local",
						namespace:      GLOBAL_NAMESPACE,
						serviceAccount: "sleep",
					},
				},
			},
			true,
		},
		{
			"5-2. Principal allow mismatch, deny",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{ALLOW_POLICY: policy5_2},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				&rbacConnection{
					srcIdentity: Identity{
						trustDomain:    "cluster.local",
						namespace:      GLOBAL_NAMESPACE,
						serviceAccount: "sleep",
					},
				},
			},
			false,
		},
		{
			"5-3. Principal deny match, deny",
			fields{
				&policyStore{
					byKey: map[string]authPolicy{
						DENY_POLICY:  policy5_3_deny,
						ALLOW_POLICY: policy5_3_allow,
					},
					byNamespace: byNamespaceAllowDeny,
				},
			},
			args{
				&rbacConnection{
					srcIdentity: Identity{
						trustDomain:    "cluster.local",
						namespace:      GLOBAL_NAMESPACE,
						serviceAccount: "sleep",
					},
				},
			},
			false,
		},
		{
			"5-4. Principal deny mismatch, allow",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{DENY_POLICY: policy5_4},
					byNamespace: byNamespaceDeny,
				},
			},
			args{
				&rbacConnection{
					srcIdentity: Identity{
						trustDomain:    "cluster.local",
						namespace:      GLOBAL_NAMESPACE,
						serviceAccount: "sleep",
					},
				},
			},
			true,
		},

		{
			"6-1. Namespace allow match, allow",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{ALLOW_POLICY: policy6_1},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				&rbacConnection{srcIdentity: Identity{namespace: GLOBAL_NAMESPACE}},
			},
			true,
		},
		{
			"6-2. Namespace allow mismatch, deny",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{ALLOW_POLICY: policy6_2},
					byNamespace: byNamespaceAllow,
				},
			},
			args{&rbacConnection{srcIdentity: Identity{namespace: GLOBAL_NAMESPACE}}},
			false,
		},
		{
			"6-3. Namespace deny match, deny",
			fields{
				&policyStore{
					byKey: map[string]authPolicy{
						DENY_POLICY:  policy6_3_deny,
						ALLOW_POLICY: policy6_3_allow,
					},
					byNamespace: byNamespaceAllowDeny,
				},
			},
			args{&rbacConnection{srcIdentity: Identity{namespace: GLOBAL_NAMESPACE}}},
			false,
		},
		{
			"6-4. Namespace deny mismatch, allow",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{DENY_POLICY: policy6_4},
					byNamespace: byNamespaceDeny,
				},
			},
			args{&rbacConnection{srcIdentity: Identity{namespace: GLOBAL_NAMESPACE}}},
			true,
		},

		{
			"7-1. Test rules OR-ed allow, 1 rule matches, allow",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{ALLOW_POLICY: policy7_1},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				&rbacConnection{
					dstIp: []byte{192, 168, 122, 2},
					srcIp: []byte{192, 168, 122, 4},
				},
			},
			true,
		},
		{
			"7-2. Test rules OR-ed allow, no rule matches, deny",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{ALLOW_POLICY: policy7_2},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				&rbacConnection{
					dstIp: []byte{192, 168, 122, 2},
					srcIp: []byte{192, 168, 122, 5},
				},
			},
			false,
		},
		{
			"7-3. Test rules OR-ed deny, 1 rule matches, deny",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{DENY_POLICY: policy7_3},
					byNamespace: byNamespaceDeny,
				},
			},
			args{
				&rbacConnection{
					dstIp: []byte{192, 168, 122, 2},
					srcIp: []byte{192, 168, 122, 4},
				},
			},
			false,
		},
		{
			"7-4. Test rules OR-ed deny, no rule matches, allow",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{DENY_POLICY: policy7_4},
					byNamespace: byNamespaceDeny,
				},
			},
			args{
				&rbacConnection{
					dstIp: []byte{192, 168, 122, 2},
					srcIp: []byte{192, 168, 122, 5},
				},
			},
			true,
		},

		{
			"8-1. Test clauses AND-ed allow, 1 clause mismatches, deny",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{ALLOW_POLICY: policy8_1},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				&rbacConnection{
					dstIp: []byte{192, 168, 122, 2},
					srcIp: []byte{192, 168, 122, 4},
				},
			},
			false,
		},
		{
			"8-2. Test clauses AND-ed allow, all clauses match, allow",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{ALLOW_POLICY: policy8_2},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				&rbacConnection{
					dstIp: []byte{192, 168, 122, 2},
					srcIp: []byte{192, 168, 122, 3},
				},
			},
			true,
		},
		{
			"8-3. Test clauses AND-ed deny, 1 clause mismatch, allow",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{DENY_POLICY: policy8_3},
					byNamespace: byNamespaceDeny,
				},
			},
			args{
				&rbacConnection{
					dstIp: []byte{192, 168, 122, 2},
					srcIp: []byte{192, 168, 122, 4},
				},
			},
			true,
		},
		{
			"8-4. Test clauses AND-ed deny, all clauses match, deny",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{DENY_POLICY: policy8_4},
					byNamespace: byNamespaceDeny,
				},
			},
			args{
				&rbacConnection{
					dstIp: []byte{192, 168, 122, 2},
					srcIp: []byte{192, 168, 122, 3},
				},
			},
			false,
		},

		{
			"9-1. Test matches OR-ed allow, 1 match matches, allow",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{ALLOW_POLICY: policy9_1},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				&rbacConnection{
					dstIp: []byte{192, 168, 122, 2},
					srcIp: []byte{192, 168, 122, 4},
				},
			},
			true,
		},
		{
			"9-2. Test matches OR-ed allow, no match matches, deny",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{ALLOW_POLICY: policy9_2},
					byNamespace: byNamespaceAllow,
				},
			},
			args{
				&rbacConnection{
					dstIp: []byte{192, 168, 122, 2},
					srcIp: []byte{192, 168, 122, 5},
				},
			},
			false,
		},
		{
			"9-3. Test matches OR-ed deny, 1 match matches, deny",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{DENY_POLICY: policy9_3},
					byNamespace: byNamespaceDeny,
				},
			},
			args{
				&rbacConnection{
					dstIp: []byte{192, 168, 122, 2},
					srcIp: []byte{192, 168, 122, 4},
				},
			},
			false,
		},
		{
			"9-4. Test matches OR-ed deny, no match matches, allow",
			fields{
				&policyStore{
					byKey:       map[string]authPolicy{DENY_POLICY: policy9_4},
					byNamespace: byNamespaceDeny,
				},
			},
			args{
				&rbacConnection{
					dstIp: []byte{192, 168, 122, 2},
					srcIp: []byte{192, 168, 122, 5},
				},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rbac := &Rbac{
				policyStore:   tt.fields.policyStore,
				workloadCache: cache.NewWorkloadCache(),
			}
			if got := rbac.doRbac(tt.args.conn); got != tt.want {
				t.Errorf("Rbac.DoRbac() = %v, want %v", got, tt.want)
			}
		})
	}
}
