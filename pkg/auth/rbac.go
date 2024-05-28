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
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf/ringbuf"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/api/v2/workloadapi/security"
	"kmesh.net/kmesh/pkg/bpf"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/nets"
)

const (
	SPIFFE_PREFIX = "spiffe://"
	MSG_TYPE_IPV4 = 0
	MSG_TYPE_IPV6 = 1
	// IPV4_TUPLE_LENGTH is the fixed length of IPv4 source/destination address(4 bytes each) and port(2 bytes each)
	IPV4_TUPLE_LENGTH = 12
	// MSG_LEN is the fixed length of one record we retrieve from map of tuple
	MSG_LEN = 40
)

var (
	log = logger.NewLoggerField("pkg/auth")
)

type Rbac struct {
	policyStore   *policyStore
	workloadCache cache.WorkloadCache
	bpfWorkload   *bpf.BpfKmeshWorkload
}

type Identity struct {
	trustDomain    string
	namespace      string
	serviceAccount string
}

type rbacConnection struct {
	srcIdentity Identity
	dstNetwork  string
	srcIp       []byte
	dstIp       []byte
	dstPort     uint32
}

func NewRbac(workloadObj *bpf.BpfKmeshWorkload, workloadCache cache.WorkloadCache) *Rbac {
	return &Rbac{
		policyStore:   newPolicystore(),
		workloadCache: workloadCache,
		bpfWorkload:   workloadObj,
	}
}

func (r *Rbac) Run(ctx context.Context) {
	if r == nil {
		return
	}
	reader, err := ringbuf.NewReader(r.bpfWorkload.SockOps.MapOfTuple)
	if err != nil {
		log.Errorf("open ringbuf map FAILED, err: %v", err)
		return
	}
	defer func() {
		if err := reader.Close(); err != nil {
			log.Errorf("reader Close FAILED, err: %v", err)
		}
	}()

	rec := ringbuf.Record{}
	tupleV4, tupleV6 := bpfSockTupleV4{}, bpfSockTupleV6{}
	var conn rbacConnection
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if err = reader.ReadInto(&rec); err != nil {
				log.Errorf("ringbuf reader FAILED to read, err: %v", err)
				continue
			}

			if len(rec.RawSample) != MSG_LEN {
				log.Errorf("wrong length %v of a msg...", len(rec.RawSample))
				continue
			}
			msgType := binary.LittleEndian.Uint32(rec.RawSample)
			var buf *bytes.Buffer
			switch msgType {
			case MSG_TYPE_IPV4:
				buf = bytes.NewBuffer(rec.RawSample[4 : IPV4_TUPLE_LENGTH+4+1])
				if err = binary.Read(buf, binary.LittleEndian, &tupleV4); err != nil {
					log.Errorf("deserialize IPv4 FAILED, err: %v", err)
					continue
				}
				conn = buildConnV4(&tupleV4)
			case MSG_TYPE_IPV6:
				buf = bytes.NewBuffer(rec.RawSample[4:])
				if err = binary.Read(buf, binary.LittleEndian, &tupleV6); err != nil {
					log.Errorf("deserialize IPv6 FAILED, err: %v", err)
					continue
				}
				conn = buildConnV6(&tupleV6)
			default:
				log.Errorf("INVALID msg type: %v", msgType)
				continue
			}

			if !r.doRbac(&conn) {
				switch msgType {
				case MSG_TYPE_IPV4:
					if err = xdpNotifyConnRstV4(&xdpHandlerKeyV4{Tuple: tupleV4}); err != nil {
						log.Errorf("XdpHandlerUpdateV4 FAILED, err: %v", err)
						continue
					}
				case MSG_TYPE_IPV6:
					if err = xdpNotifyConnRstV6(&xdpHandlerKeyV6{tuple: tupleV6}); err != nil {
						log.Errorf("XdpHandlerUpdateV6 FAILED, err: %v", err)
						continue
					}
				default:
					log.Errorf("INVALID msg type: %v", msgType)
					continue
				}
			}
		}
	}
}

func (r *Rbac) UpdatePolicy(auth *security.Authorization) error {
	return r.policyStore.updatePolicy(auth)
}

func (r *Rbac) RemovePolicy(policyKey string) {
	r.policyStore.removePolicy(policyKey)
}

func (r *Rbac) doRbac(conn *rbacConnection) bool {
	var dstWorkload *workloadapi.Workload
	if len(conn.dstIp) > 0 {
		dstWorkload = r.workloadCache.GetWorkloadByAddr(cache.NetworkAddress{
			Network: conn.dstNetwork,
			Address: nets.ConvertIpByteToUint32(conn.dstIp),
		})
	}

	allowPolicies, denyPolicies := r.aggregate(dstWorkload)

	// 1. If there is ANY deny policy, deny the request
	for _, denyPolicy := range denyPolicies {
		if matches(conn, denyPolicy) {
			return false
		}
	}

	// 2. If there is NO allow policy for the workload, allow the request
	if len(allowPolicies) == 0 {
		return true
	}

	// 3. If there is ANY allow policy matched, allow the request
	for _, allowPolicy := range allowPolicies {
		if matches(conn, allowPolicy) {
			return true
		}
	}

	// 4. If 1,2 and 3 unsatisfied, deny the request
	return false
}

func (r *Rbac) aggregate(workload *workloadapi.Workload) (allowPolicies, denyPolicies []authPolicy) {
	allowPolicies = make([]authPolicy, 0)
	denyPolicies = make([]authPolicy, 0)

	// Collect policy names from workload, global namespace and namespace
	policyNames := r.policyStore.getByNamesapce("").UnsortedList()
	if workload != nil {
		policyNames = append(append(policyNames,
			r.policyStore.getByNamesapce(workload.Namespace).UnsortedList()...),
			workload.GetAuthorizationPolicies()...)
	}

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

func matches(conn *rbacConnection, policy authPolicy) bool {
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
				if matchDstIp(conn.dstIp, match) && matchSrcIp(conn.srcIp, match) &&
					matchDstPort(conn.dstPort, match) && matchPrincipal(conn.srcIdentity.String(), match) &&
					matchNamespace(conn.srcIdentity.namespace, match) {
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

func buildConnV4(tupleV4 *bpfSockTupleV4) rbacConnection {
	conn := rbacConnection{}
	conn.srcIp = binary.LittleEndian.AppendUint32(conn.srcIp, tupleV4.SrcAddr)
	conn.dstIp = binary.LittleEndian.AppendUint32(conn.dstIp, tupleV4.DstAddr)
	conn.dstPort = uint32(tupleV4.DstPort<<8 | tupleV4.DstPort>>8)
	return conn
}

func buildConnV6(tupleV6 *bpfSockTupleV6) rbacConnection {
	conn := rbacConnection{}
	for i := range tupleV6.SrcAddr {
		conn.srcIp = binary.LittleEndian.AppendUint32(conn.srcIp, tupleV6.SrcAddr[4-i])
		conn.dstIp = binary.LittleEndian.AppendUint32(conn.dstIp, tupleV6.DstAddr[4-i])
	}
	conn.dstPort = uint32(tupleV6.DstPort<<8 | tupleV6.DstPort>>8)
	return conn
}

func (id *Identity) String() string {
	return fmt.Sprintf(SPIFFE_PREFIX+"%s/ns/%s/sa/%s", id.trustDomain, id.namespace, id.serviceAccount)
}

func isEmptyMatch(m *security.Match) bool {
	return m.GetDestinationIps() == nil && m.GetNotDestinationIps() == nil &&
		m.GetSourceIps() == nil && m.GetNotSourceIps() == nil &&
		m.GetDestinationPorts() == nil && m.GetNotDestinationPorts() == nil &&
		m.GetPrincipals() == nil && m.GetNotPrincipals() == nil &&
		m.GetNamespaces() == nil && m.GetNotNamespaces() == nil
}
