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
	"net"
	"strings"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/api/v2/workloadapi/security"
	"kmesh.net/kmesh/pkg/logger"
)

const (
	SPIFFE_PREFIX = "spiffe://"
)

var (
	log = logger.NewLoggerField("pkg/auth")
)

type Rbac struct {
	policyStore *policyStore
}

func NewRbac() *Rbac {
	return &Rbac{
		policyStore: newPolicystore(),
	}
}

func (r *Rbac) DoRbac(conn *RbacConnection) bool {
	workload := conn.fetchWorkload()
	allowPolices, denyPolicies := r.aggregate(workload)

	// 1. If there is ANY deny policy, deny the request
	for _, denyPolicy := range denyPolicies {
		if matches(conn, denyPolicy) {
			return false
		}
	}

	// 2. If there is NO allow policy for the workload, allow the request
	if len(allowPolices) == 0 {
		return true
	}

	// 3. If there is ANY allow policy matched, allow the request
	for _, allowPolicy := range allowPolices {
		if matches(conn, allowPolicy) {
			return true
		}
	}

	// 4. If 1,2 and 3 unsatisfied, deny the request
	return false
}

func (r *Rbac) UpdatePolicy(auth *security.Authorization) error {
	return r.policyStore.updatePolicy(auth)
}

func (r *Rbac) RemovePolicy(policyKey string) {
	r.policyStore.removePolicy(policyKey)
}

func (r *Rbac) aggregate(workload *workloadapi.Workload) (allowPolicies, denyPolicies []authPolicy) {
	// Collect policy names from workload, global namespace and namespace
	policyNames := workload.GetAuthorizationPolicies()
	policyNames = append(policyNames, r.policyStore.getByNamesapce("").UnsortedList()...)
	policyNames = append(policyNames, r.policyStore.getByNamesapce(workload.Namespace).UnsortedList()...)

	allowPolicies = make([]authPolicy, 0)
	denyPolicies = make([]authPolicy, 0)
	for _, policyName := range policyNames {
		if policy, ok := r.policyStore.byKey[policyName]; ok {
			if policy.Action == security.Action_ALLOW {
				allowPolicies = append(allowPolicies, policy)
			} else if policy.Action == security.Action_DENY {
				denyPolicies = append(denyPolicies, policy)
			}
		}
	}
	return
}

func matches(conn *RbacConnection, policy authPolicy) bool {
	if policy.GetRules() == nil {
		return false
	}

	// If ANY rule matches, it's a match
	for _, rule := range policy.GetRules() {
		ruleMatch := true
		// If ALL clause matches, it's a match
		for _, clause := range rule.GetClauses() {
			clauseMatch := false
			// If ANY match matches, it's a match
			for _, match := range clause.GetMatches() {
				if isEmptyMatch(match) {
					continue
				}

				// Values of specific type are OR-ed. If multiple types are set, they are AND-ed
				// If one type fails to match, we do a short circuit
				if matchDstIp(conn.DstIp, match) && matchSrcIp(conn.SrcIp, match) &&
					matchDstPort(conn.DstPort, match) && matchPrincipal(conn.SrcIdentity.String(), match) &&
					matchNamespace(conn.SrcIdentity.namespace, match) {
					clauseMatch = true
					break
				}
				// Continue to try next match
			}

			if len(clause.GetMatches()) == 0 {
				clauseMatch = true
			}
			ruleMatch = ruleMatch && clauseMatch
			if !ruleMatch {
				break
			}
		}
		if ruleMatch {
			return true
		}
	}
	return false
}

func matchDstIp(dstIp []byte, match *security.Match) bool {
	var pm, nm bool
	// Positive match means if ANY destination IP in destination_ips contains dstIp, it does match
	// If there is no destination IP in destination_ips, it does match
	if len(match.GetDestinationIps()) == 0 {
		pm = true
	} else {
		pm = internalMatchDstIp(dstIp, match.GetDestinationIps())
	}
	// Negative match means if ANY destination IP in not_destination_ips contains dstIp, it does NOT match
	// If there is no destination IP in destination_ips, it does match
	if len(match.GetNotDestinationIps()) == 0 {
		nm = true
	} else {
		nm = !internalMatchDstIp(dstIp, match.GetNotDestinationIps())
	}
	return pm && nm
}

func matchSrcIp(srcIp []byte, match *security.Match) bool {
	var pm, nm bool
	// Positive match means if ANY source IP in source_ips contains srcIp, it does match
	// If there is no source IP in source_ips, it does match
	if len(match.GetSourceIps()) == 0 {
		pm = true
	} else {
		pm = internalMatchSrcIp(srcIp, match.GetSourceIps())
	}
	// Negative match means if ANY source IP in not_source_ips contains srcIp, it does NOT match
	// If there is no source IP in not_source_ips, it does match
	if len(match.GetNotSourceIps()) == 0 {
		nm = true
	} else {
		nm = !internalMatchSrcIp(srcIp, match.GetNotSourceIps())
	}
	return pm && nm
}

func matchDstPort(dstPort uint32, match *security.Match) bool {
	var pm, nm bool
	// Positive match means if ANY destination port in destination_ports equals to dstPort, it does match
	// If there is no destination port in destination_ports, it does match
	if len(match.GetDestinationPorts()) == 0 {
		pm = true
	} else {
		pm = internalMatchDstPort(dstPort, match.GetDestinationPorts())
	}
	// Negative match means if ANY destination port in not_destination_ports equals to dstPort, it does NOT match
	// If there is no destination port in not_destination_ports, it does match
	if len(match.GetNotDestinationPorts()) == 0 {
		nm = true
	} else {
		nm = !internalMatchDstPort(dstPort, match.GetNotDestinationPorts())
	}
	return pm && nm
}

func matchPrincipal(srcId string, match *security.Match) bool {
	// Source identity must start with "spiffe://"
	if !strings.HasPrefix(srcId, SPIFFE_PREFIX) {
		return false
	}

	var pm, nm bool
	// Positive match means if ANY principal pattern in principals matches srcId, it does match
	// If there is no principal pattern in principals, it does match
	if len(match.GetPrincipals()) == 0 {
		pm = true
	} else {
		pm = internalMatchPrincipal(srcId, match.GetPrincipals())
	}
	// Negative match means if ANY principal pattern in not_principals matches srcId, it does NOT match
	// If there is no principal pattern in not_principals, it does match
	if len(match.GetNotPrincipals()) == 0 {
		nm = true
	} else {
		nm = !internalMatchPrincipal(srcId, match.GetNotPrincipals())
	}
	return pm && nm
}

func matchNamespace(srcNs string, match *security.Match) bool {
	var pm, nm bool
	// Positive match means if ANY namesapce pattern in namespaces matches srcNs, it does match
	// If there is no namespace pattern in namespaces, it does match
	if len(match.GetNamespaces()) == 0 {
		pm = true
	} else {
		pm = internalMatchNamespace(srcNs, match.GetNamespaces())
	}
	// Negative match means if ANY namesapce pattern in not_namespaces matches srcNs, it does NOT match
	// If there is no namespace pattern in not_namespaces, it does match
	if len(match.GetNotNamespaces()) == 0 {
		nm = true
	} else {
		nm = !internalMatchNamespace(srcNs, match.GetNotNamespaces())
	}
	return pm && nm
}

func internalMatchDstIp(dstIp []byte, addresses []*security.Address) bool {
	for _, addr := range addresses {
		_, ipNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", net.IP(addr.GetAddress()).String(), addr.GetLength()))
		if err != nil {
			continue
		}
		if ipNet.Contains(dstIp) {
			return true
		}
	}
	return false
}

func internalMatchSrcIp(srcIp []byte, addresses []*security.Address) bool {
	for _, addr := range addresses {
		_, ipNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", net.IP(addr.GetAddress()).String(), addr.GetLength()))
		if err != nil {
			continue
		}
		if ipNet.Contains(srcIp) {
			return true
		}
	}
	return false
}

func internalMatchDstPort(checkDstPort uint32, dstPorts []uint32) bool {
	for _, port := range dstPorts {
		if checkDstPort == port {
			return true
		}
	}
	return false
}

func internalMatchPrincipal(srcId string, principals []*security.StringMatch) bool {
	srcId = strings.TrimPrefix(srcId, SPIFFE_PREFIX)
	m := false
	for _, principal := range principals {
		if len(principal.GetPrefix()) > 0 {
			m = strings.HasPrefix(srcId, principal.GetPrefix())
		} else if len(principal.GetSuffix()) > 0 {
			m = strings.HasSuffix(srcId, principal.GetSuffix())
		} else if len(principal.GetExact()) > 0 {
			m = srcId == principal.GetExact()
		} else {
			m = len(srcId) == 0
		}
		if m {
			return true
		}
	}
	return false
}

func internalMatchNamespace(srcNs string, namespaces []*security.StringMatch) bool {
	m := false
	for _, ns := range namespaces {
		if len(ns.GetPrefix()) > 0 {
			m = strings.HasPrefix(srcNs, ns.GetPrefix())
		} else if len(ns.GetSuffix()) > 0 {
			m = strings.HasSuffix(srcNs, ns.GetSuffix())
		} else if len(ns.GetExact()) > 0 {
			m = srcNs == ns.GetExact()
		} else {
			m = len(srcNs) == 0
		}
		if m {
			return true
		}
	}
	return false
}

type Identity struct {
	trustDomain    string
	namespace      string
	serviceAccount string
}

func (id *Identity) String() string {
	return fmt.Sprintf(SPIFFE_PREFIX+"%s/ns/%s/sa/%s", id.trustDomain, id.namespace, id.serviceAccount)
}

type RbacConnection struct {
	SrcIdentity Identity
	SrcIp       []byte
	DstIp       []byte
	DstPort     uint32
}

// fetchWorkload fetches workload proto model by dstIP & dstPort
// Since the workload API has not been finished yet, we do MOCK here
func (rc *RbacConnection) fetchWorkload() *workloadapi.Workload {
	KMESH_NAMESPACE := "kmesh-system"
	return &workloadapi.Workload{Namespace: KMESH_NAMESPACE}
}

func isEmptyMatch(m *security.Match) bool {
	return m.GetDestinationIps() == nil && m.GetNotDestinationIps() == nil &&
		m.GetSourceIps() == nil && m.GetNotSourceIps() == nil &&
		m.GetDestinationPorts() == nil && m.GetNotDestinationPorts() == nil &&
		m.GetPrincipals() == nil && m.GetNotPrincipals() == nil &&
		m.GetNamespaces() == nil && m.GetNotNamespaces() == nil
}
