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
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/api/v2/workloadapi/security"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
	"kmesh.net/kmesh/pkg/logger"
)

const (
	SPIFFE_PREFIX = "spiffe://"
	// IPV4_TUPLE_LENGTH is the fixed length of IPv4 source/destination address(4 bytes each) and port(2 bytes each)
	IPV4_TUPLE_LENGTH = int(unsafe.Sizeof(bpfSockTupleV4{}))
	// TUPLE_LEN is the fixed length of 4-tuple(source/dest IP/port) in a record from map of tuple
	TUPLE_LEN = int(unsafe.Sizeof(bpfSockTupleV6{}))
	// MSG_LEN is the fixed length of one record we retrieve from map of tuple
	MSG_LEN = TUPLE_LEN + int(unsafe.Sizeof(constants.MSG_TYPE_IPV4))
)

var (
	log          = logger.NewLoggerScope("auth")
	nativeEndian binary.ByteOrder
)

func init() {
	// Detect the native byte order of the host at startup.
	// This is needed because BPF sends ports in host byte order.
	i := int16(1)
	if *(*byte)(unsafe.Pointer(&i)) == 1 {
		nativeEndian = binary.LittleEndian
	} else {
		nativeEndian = binary.BigEndian
	}
}

type Rbac struct {
	policyStore   *policyStore
	workloadCache cache.WorkloadCache
	notifyFunc    notifyFunc
}

type Identity struct {
	trustDomain    string
	namespace      string
	serviceAccount string
}

type rbacConnection struct {
	srcIdentity Identity
	dstNetwork  string
	// srcIp is big endian
	srcIp []byte
	// dstIp ip is big endian
	dstIp []byte
	// dstPort is little endian
	dstPort uint32
}

type bpfSockTupleV4 struct {
	// SrcAddr and DstAddr are in network byte order (big endian).
	// SrcPort and DstPort are in host byte order.
	SrcAddr uint32
	DstAddr uint32
	SrcPort uint16
	DstPort uint16
}

type bpfSockTupleV6 struct {
	// SrcAddr and DstAddr are in network byte order (big endian).
	// SrcPort and DstPort are in host byte order.
	SrcAddr [4]uint32
	DstAddr [4]uint32
	SrcPort uint16
	DstPort uint16
}

func NewRbac(workloadCache cache.WorkloadCache) *Rbac {
	return &Rbac{
		policyStore:   newPolicyStore(),
		workloadCache: workloadCache,
		notifyFunc:    xdpNotifyConnRst,
	}
}

func (r *Rbac) Run(ctx context.Context, authReq, authRes *ebpf.Map) {
	if r == nil {
		return
	}
	if authReq == nil || authRes == nil {
		log.Error("either km_auth_req or km_auth_res map is nil")
		return
	}
	reader, err := ringbuf.NewReader(authReq)
	if err != nil {
		log.Errorf("open km_auth_req ringbuf err: %v", err)
		return
	}
	defer func() {
		_ = reader.Close()
	}()

	rec := ringbuf.Record{}
	var conn rbacConnection
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if err = reader.ReadInto(&rec); err != nil {
				log.Errorf("km_auth_req read failed: %v", err)
				continue
			}
			if len(rec.RawSample) != MSG_LEN {
				log.Errorf("wrong length %v of a msg, should be %v", len(rec.RawSample), MSG_LEN)
				continue
			}
			// RawSample is network order
			msgType := binary.LittleEndian.Uint32(rec.RawSample)
			tupleData := rec.RawSample[unsafe.Sizeof(msgType):]
			buf := bytes.NewBuffer(tupleData)
			switch msgType {
			case constants.MSG_TYPE_IPV4:
				conn, err = r.buildConnV4(buf)
			case constants.MSG_TYPE_IPV6:
				conn, err = r.buildConnV6(buf)
			default:
				log.Error("invalid msg type: ", msgType)
				continue
			}
			if err != nil {
				continue
			}

			if !r.doRbac(&conn) {
				log.Debugf("Auth denied for connection: %+v", conn)
				// If conn is denied, write tuples into XDP map, which includes source/destination IP/Port
				if err = r.notifyFunc(authRes, msgType, tupleData); err != nil {
					log.Error("km_auth_res update FAILED, err: ", err)
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

// GetAllPolicies returns all policy names in the policy store
func (r *Rbac) GetAllPolicies() map[string]string {
	if r == nil {
		return nil
	}
	return r.policyStore.getAllPolicies()
}

func (r *Rbac) doRbac(conn *rbacConnection) bool {
	var networkAddress cache.NetworkAddress
	networkAddress.Network = conn.dstNetwork
	networkAddress.Address, _ = netip.AddrFromSlice(conn.dstIp)
	dstWorkload := r.workloadCache.GetWorkloadByAddr(networkAddress)
	// If no workload found, deny
	if dstWorkload == nil {
		log.Debugf("denied for connection: %v because destination workload not found", conn)
		return false
	}

	// TODO: maybe cache them for performance issue
	allowPolicies, denyPolicies := r.aggregate(dstWorkload)

	// 1. If there is ANY deny policy, deny the request
	for _, denyPolicy := range denyPolicies {
		if matches(conn, denyPolicy) {
			log.Infof("Auth denied for connection: %+v because authorization policy", conn)
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

func (r *Rbac) aggregate(workload *workloadapi.Workload) (allowPolicies, denyPolicies []*security.Authorization) {
	allowPolicies = make([]*security.Authorization, 0)
	denyPolicies = make([]*security.Authorization, 0)

	// Collect policy names from workload,  namespace and global(root namespace)
	policyNames := workload.GetAuthorizationPolicies()
	policyNames = append(policyNames, r.policyStore.getByNamespace(workload.Namespace)...)
	policyNames = append(policyNames, r.policyStore.getByNamespace("")...)

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

func matches(conn *rbacConnection, policy *security.Authorization) bool {
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
	// Positive match means if ANY namespace pattern in namespaces matches srcNs, it does match
	// If there is no namespace pattern in namespaces, it does match
	if len(match.GetNamespaces()) == 0 {
		pm = true
	} else {
		pm = internalMatchNamespace(srcNs, match.GetNamespaces())
	}
	// Negative match means if ANY namespace pattern in not_namespaces matches srcNs, it does NOT match
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

func (r *Rbac) buildConnV4(buf *bytes.Buffer) (rbacConnection, error) {
	var (
		conn    rbacConnection
		tupleV4 bpfSockTupleV4
	)
	// SrcAddr and DstAddr are BigEndian, but Ports are Host Byte Order (LittleEndian on x86)
	// We read each field accordingly.
	if err := binary.Read(buf, binary.BigEndian, &tupleV4.SrcAddr); err != nil {
		return conn, err
	}
	if err := binary.Read(buf, binary.BigEndian, &tupleV4.DstAddr); err != nil {
		return conn, err
	}
	if err := binary.Read(buf, nativeEndian, &tupleV4.SrcPort); err != nil {
		return conn, err
	}
	if err := binary.Read(buf, nativeEndian, &tupleV4.DstPort); err != nil {
		return conn, err
	}

	conn.srcIp = binary.BigEndian.AppendUint32(conn.srcIp, tupleV4.SrcAddr)
	conn.dstIp = binary.BigEndian.AppendUint32(conn.dstIp, tupleV4.DstAddr)
	conn.dstPort = uint32(tupleV4.DstPort)
	conn.srcIdentity = r.getIdentityByIp(conn.srcIp)
	return conn, nil
}

func (r *Rbac) buildConnV6(buf *bytes.Buffer) (rbacConnection, error) {
	var (
		conn    rbacConnection
		tupleV6 bpfSockTupleV6
	)

	// SrcAddr and DstAddr are BigEndian, but Ports are in Host Byte Order
	if err := binary.Read(buf, binary.BigEndian, &tupleV6.SrcAddr); err != nil {
		return conn, err
	}
	if err := binary.Read(buf, binary.BigEndian, &tupleV6.DstAddr); err != nil {
		return conn, err
	}
	if err := binary.Read(buf, nativeEndian, &tupleV6.SrcPort); err != nil {
		return conn, err
	}
	if err := binary.Read(buf, nativeEndian, &tupleV6.DstPort); err != nil {
		return conn, err
	}

	// srcIp and dstIp are big endian
	for i := range tupleV6.SrcAddr {
		conn.srcIp = binary.BigEndian.AppendUint32(conn.srcIp, tupleV6.SrcAddr[i])
		conn.dstIp = binary.BigEndian.AppendUint32(conn.dstIp, tupleV6.DstAddr[i])
	}
	conn.dstPort = uint32(tupleV6.DstPort)
	// conn.dstIp = restoreIPv4(conn.dstIp)
	// conn.srcIp = restoreIPv4(conn.srcIp)
	conn.srcIdentity = r.getIdentityByIp(conn.srcIp)

	return conn, nil
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

// todo : get identity from tls connection
func (r *Rbac) getIdentityByIp(ip []byte) Identity {
	var networkAddress cache.NetworkAddress
	networkAddress.Address, _ = netip.AddrFromSlice(ip)
	workload := r.workloadCache.GetWorkloadByAddr(networkAddress)
	if workload == nil {
		log.Debugf("cannot find workload %v", networkAddress.Address.String())
		return Identity{}
	}
	return Identity{
		trustDomain:    workload.GetTrustDomain(),
		namespace:      workload.GetNamespace(),
		serviceAccount: workload.GetServiceAccount(),
	}
}

// List returns a copied list of all policies
func (r *Rbac) PoliciesList() []*security.Authorization {
	return r.policyStore.list()
}
