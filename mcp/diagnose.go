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

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kmesh.net/kmesh/pkg/constants"
)

// diagEndpoint is the resolved identity of one side of a connectivity check.
type diagEndpoint struct {
	Found     bool   `json:"found"`
	Kind      string `json:"kind,omitempty"` // workload | service
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Status    string `json:"status,omitempty"`
	Addresses string `json:"addresses,omitempty"`
	VIPs      string `json:"vips,omitempty"`
	Waypoint  string `json:"waypoint,omitempty"`
}

type diagPolicy struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Action    string `json:"action,omitempty"`
	Scope     string `json:"scope,omitempty"`
}

type diagnoseOutput struct {
	Mode     string         `json:"mode"`
	Source   diagEndpoint   `json:"source"`
	Target   diagEndpoint   `json:"target"`
	BpfState map[string]any `json:"bpfState,omitempty"`
	Policies []diagPolicy   `json:"policies,omitempty"`
	Verdict  string         `json:"verdict"`
	Hints    []string       `json:"hints"`
}

// HandleDiagnoseConnectivity explains why traffic from source to target may fail.
func (h *McpHandler) HandleDiagnoseConnectivity(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	source, err := req.RequireString("source")
	if err != nil {
		return mcp.NewToolResultError("source argument is required"), nil
	}
	target, err := req.RequireString("target")
	if err != nil {
		return mcp.NewToolResultError("target argument is required"), nil
	}
	podName := req.GetString("podName", "")
	namespace := req.GetString("namespace", "")

	if err := validateK8sName("podName", podName); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if err := validateK8sName("namespace", namespace); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// namespace only qualifies resource names; the daemon uses its own namespace.
	mode, err := h.detectMode(ctx, podName, "")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("could not verify daemon mode: %v", err)), nil
	}

	if mode == "kernel-native" {
		return h.diagnoseKernelNative(ctx, podName, source, target)
	}
	return h.diagnoseDualEngine(ctx, podName, source, target, namespace)
}

func (h *McpHandler) diagnoseDualEngine(ctx context.Context, podName, source, target, defaultNS string) (*mcp.CallToolResult, error) {
	dumpRaw, err := h.fetchFromDaemon(ctx, podName, "", "debug/config_dump/dual-engine")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch workload dump: %v", err)), nil
	}
	bpfRaw, err := h.fetchFromDaemon(ctx, podName, "", "debug/config_dump/bpf/dual-engine")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch BPF maps: %v", err)), nil
	}

	var dump any
	if err := json.Unmarshal(dumpRaw, &dump); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to parse workload dump: %v", err)), nil
	}
	var bpf any
	if err := json.Unmarshal(bpfRaw, &bpf); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to parse BPF maps: %v", err)), nil
	}
	dumpCats := collectCategories(dump)
	bpfCats := collectCategories(bpf)

	src, srcKind := resolveEndpoint(dumpCats, source, true, defaultNS)
	dst, dstKind := resolveEndpoint(dumpCats, target, false, defaultNS)

	out := diagnoseOutput{
		Mode:   "dual-engine",
		Source: describeEndpoint(src, srcKind),
		Target: describeEndpoint(dst, dstKind),
	}
	out.BpfState, out.Policies, out.Verdict, out.Hints = analyzePath(src, srcKind, dst, dstKind, dumpCats, bpfCats)

	// Presence in the workload cache does not imply the namespace is enrolled.
	if src != nil {
		if enrolled, known := h.namespaceEnrolled(ctx, strField(src, "namespace")); known && !enrolled {
			out.Verdict = "source-not-enrolled"
			out.Hints = append(out.Hints,
				fmt.Sprintf("Namespace %q is not enrolled in the mesh (missing the %s=%s label), so the source's traffic may bypass the Kmesh data plane. Enroll it and restart the pod.",
					strField(src, "namespace"), constants.DataPlaneModeLabel, constants.DataPlaneModeKmesh))
		}
	}
	if out.Verdict != "source-not-enrolled" && dst != nil {
		if enrolled, known := h.namespaceEnrolled(ctx, strField(dst, "namespace")); known && !enrolled {
			out.Verdict = "target-not-enrolled"
			out.Hints = append(out.Hints,
				fmt.Sprintf("Namespace %q is not enrolled in the mesh (missing the %s=%s label), so traffic to the target may bypass the Kmesh data plane.",
					strField(dst, "namespace"), constants.DataPlaneModeLabel, constants.DataPlaneModeKmesh))
		}
	}
	return marshalToolJSON(out)
}

// namespaceEnrolled reports whether a namespace carries the mesh enrollment label.
func (h *McpHandler) namespaceEnrolled(ctx context.Context, ns string) (enrolled, known bool) {
	if ns == "" || h.cliClient == nil {
		return false, false
	}
	namespace, err := h.cliClient.Kube().CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
	if err != nil {
		return false, false
	}
	return strings.EqualFold(namespace.Labels[constants.DataPlaneModeLabel], constants.DataPlaneModeKmesh), true
}

func (h *McpHandler) diagnoseKernelNative(ctx context.Context, podName, source, target string) (*mcp.CallToolResult, error) {
	raw, err := h.fetchFromDaemon(ctx, podName, "", "debug/config_dump/kernel-native")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch config dump: %v", err)), nil
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to parse config dump: %v", err)), nil
	}

	matches := map[string]int{}
	total := 0
	for cat, items := range collectCategories(decoded) {
		n := 0
		for _, it := range items {
			if itemMatches(it, target) {
				n++
			}
		}
		if n > 0 {
			matches[cat] = n
			total += n
		}
	}

	out := map[string]any{
		"mode":    "kernel-native",
		"source":  source,
		"target":  target,
		"matches": matches,
		"verdict": "needs-manual-inspection",
		"hints": []string{
			fmt.Sprintf("Kernel-native mode gives xDS resources only; %d entries mention the target. Use get_bpf_ads_details with filter=%q for raw map state.", total, target),
			"Deep source-to-target analysis is available in dual-engine mode.",
		},
	}
	return marshalToolJSON(out)
}

// resolveEndpoint resolves the named entity, preferring defaultNS for unqualified names.
func resolveEndpoint(cats map[string][]map[string]any, input string, preferWorkload bool, defaultNS string) (map[string]any, string) {
	if item, kind := resolveEndpointIn(cats, input, preferWorkload, defaultNS); item != nil {
		return item, kind
	}
	if defaultNS != "" && !strings.Contains(input, ".") {
		return resolveEndpointIn(cats, input, preferWorkload, "")
	}
	return nil, ""
}

func resolveEndpointIn(cats map[string][]map[string]any, input string, preferWorkload bool, defaultNS string) (map[string]any, string) {
	kinds := []string{"services", "workloads"}
	matchFns := []func(map[string]any, string) bool{serviceMatches, workloadMatches}
	if preferWorkload {
		kinds = []string{"workloads", "services"}
		matchFns = []func(map[string]any, string) bool{workloadMatches, serviceMatches}
	}
	unqualified := !strings.Contains(input, ".")
	for i, kind := range kinds {
		for _, it := range cats[kind] {
			if defaultNS != "" && unqualified && strField(it, "namespace") != defaultNS {
				continue
			}
			if matchFns[i](it, input) {
				if kind == "services" {
					return it, "service"
				}
				return it, "workload"
			}
		}
	}
	return nil, ""
}

func describeEndpoint(item map[string]any, kind string) diagEndpoint {
	if item == nil {
		return diagEndpoint{Found: false}
	}
	out := diagEndpoint{
		Found:     true,
		Kind:      kind,
		Name:      strField(item, "name"),
		Namespace: strField(item, "namespace"),
		Addresses: joinClean(stringSlice(item["addresses"])),
		VIPs:      joinClean(stringSlice(item["vips"])),
	}
	if kind == "workload" {
		out.Status = strField(item, "status")
	}
	if wp := cleanAddr(strField(item, "destination")); wp != "" {
		out.Waypoint = wp
	} else if w, ok := item["waypoint"].(map[string]any); ok {
		out.Waypoint = cleanAddr(strField(w, "destination"))
	}
	return out
}

// cleanAddr drops the empty network prefix from "network/address" values.
func cleanAddr(s string) string {
	return strings.TrimPrefix(s, "/")
}

func joinClean(values []string) string {
	cleaned := make([]string, 0, len(values))
	for _, v := range values {
		cleaned = append(cleaned, cleanAddr(v))
	}
	return strings.Join(cleaned, ",")
}

// analyzePath derives the verdict and next-step hints from the resolved state.
func analyzePath(src map[string]any, srcKind string, dst map[string]any, dstKind string,
	dumpCats, bpfCats map[string][]map[string]any) (map[string]any, []diagPolicy, string, []string) {
	hints := []string{}
	bpfState := map[string]any{}
	verdict := "reachable-suspected"
	noBackends := false
	deny := false

	if src == nil {
		verdict = "source-not-enrolled"
		hints = append(hints, "Source was not found in the workload cache. Is the pod running in a Kmesh namespace? Check get_mesh_namespaces and list_daemon_pods.")
	} else if dst == nil {
		verdict = "target-not-found"
		hints = append(hints, "Target was not found as a service or workload. Check list_mesh_services for the right name.")
	}

	// BPF wiring for a service target: backends referencing the service.
	if dstKind == "service" {
		name := strField(dst, "name")
		ns := strField(dst, "namespace")
		backends := 0
		backendIPs := []string{}
		for _, b := range bpfCats["backends"] {
			for _, ref := range stringSlice(b["services"]) {
				if serviceRefMatches(ref, name, ns) {
					backends++
					if ip := strField(b, "ip"); ip != "" {
						backendIPs = append(backendIPs, ip)
					}
					break
				}
			}
		}
		sort.Strings(backendIPs)
		bpfState["backendsForTarget"] = backends
		if len(backendIPs) > 0 {
			bpfState["backendIPs"] = backendIPs
		}
		if backends == 0 {
			noBackends = true
			hints = append(hints, "The service has no backends programmed in BPF maps. Are its pods Ready and enrolled? Inspect with get_bpf_workload_details filter="+name)
		}
	}

	// Waypoint in path.
	wp := describeEndpoint(dst, dstKind).Waypoint
	if wp != "" {
		bpfState["waypoint"] = wp
		hints = append(hints, fmt.Sprintf("Traffic passes through waypoint %q. Verify it with get_waypoint_status.", wp))
	}

	// Authorization policies covering either side.
	policies := []diagPolicy{}
	for _, p := range dumpCats["policies"] {
		ns := strField(p, "namespace")
		scope := strField(p, "scope")
		covered := (src != nil && ns == strField(src, "namespace")) || (dst != nil && ns == strField(dst, "namespace"))
		// Scope values are upper case (GLOBAL, NAMESPACE, WORKLOAD_SELECTOR).
		if !covered && !strings.EqualFold(scope, "NAMESPACE") {
			covered = true
		}
		if !covered {
			continue
		}
		action := strings.ToUpper(strField(p, "action"))
		policies = append(policies, diagPolicy{
			Name:      strField(p, "name"),
			Namespace: ns,
			Action:    action,
			Scope:     scope,
		})
		if action == "DENY" {
			deny = true
		}
	}
	if deny {
		hints = append(hints, "A DENY authorization policy covers this path. Inspect it with get_authz_status and the policy rules above.")
	}

	// A DENY policy outranks missing endpoints; both hints are kept.
	switch {
	case src == nil, dst == nil:
	case deny:
		verdict = "blocked-by-policy"
	case noBackends:
		verdict = "missing-endpoints"
	}
	if verdict == "reachable-suspected" {
		hints = append(hints, "Source, target and BPF wiring all look consistent. If traffic still fails, inspect raw maps with get_bpf_workload_details using a filter.")
	}

	return bpfState, policies, verdict, hints
}

func workloadMatches(item map[string]any, input string) bool {
	ns := strField(item, "namespace")
	for _, cand := range []string{strField(item, "name"), strField(item, "workloadName"), strField(item, "uid")} {
		if nameLike(input, cand, ns) {
			return true
		}
	}
	for _, a := range stringSlice(item["addresses"]) {
		if a == input {
			return true
		}
	}
	return false
}

// serviceRefMatches reports whether a BPF backend reference points at the
// service. References appear as "name", "namespace/name",
// "namespace/name.namespace.svc.cluster.local" and similar DNS forms.
func serviceRefMatches(ref, name, namespace string) bool {
	if ref == name || ref == namespace+"/"+name {
		return true
	}
	base := ref
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		base = ref[i+1:]
	}
	if !strings.HasPrefix(base, name+".") {
		return false
	}
	// The label after the service name is the namespace, so a same-named
	// service in another namespace does not match.
	rest := base[len(name)+1:]
	nsLabel := rest
	if i := strings.Index(rest, "."); i >= 0 {
		nsLabel = rest[:i]
	}
	return nsLabel == namespace
}

func serviceMatches(item map[string]any, input string) bool {
	ns := strField(item, "namespace")
	for _, cand := range []string{strField(item, "name"), strField(item, "hostname")} {
		if nameLike(input, cand, ns) {
			return true
		}
	}
	for _, v := range stringSlice(item["vips"]) {
		if v == input {
			return true
		}
	}
	return false
}

// nameLike accepts "name", "name.namespace" and full FQDNs for a candidate.
func nameLike(input, candidate, namespace string) bool {
	if candidate == "" {
		return false
	}
	if strings.EqualFold(input, candidate) {
		return true
	}
	if strings.EqualFold(input, candidate+"."+namespace) {
		return true
	}
	if namespace != "" && strings.HasPrefix(strings.ToLower(input), strings.ToLower(candidate+"."+namespace+".")) {
		return true
	}
	return false
}

func strField(item map[string]any, key string) string {
	s, _ := item[key].(string)
	return s
}

func stringSlice(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if t != "" {
			return []string{t}
		}
	}
	return nil
}
