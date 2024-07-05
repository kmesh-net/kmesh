// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package model

import (
	"k8s.io/apimachinery/pkg/types"

	"istio.io/api/type/v1beta1"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pkg/config"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/labels"
	"istio.io/istio/pkg/config/schema/gvk"
)

// this can be any type from istio/api that uses these types of selectors
type TargetablePolicy interface {
	GetTargetRef() *v1beta1.PolicyTargetReference
	GetTargetRefs() []*v1beta1.PolicyTargetReference
	GetSelector() *v1beta1.WorkloadSelector
}

// WorkloadPolicyMatcher performs policy selection either using targetRef or label selectors.
// Label selection uses the workload labels.
// TargetRef selection uses either the workload's namespace + the gateway name based on labels,
// or the Services the workload is a part of.
type WorkloadPolicyMatcher struct {
	Namespace      string
	WorkloadLabels labels.Instance
	IsWaypoint     bool
	Service        string
}

func PolicyMatcherFor(workloadNamespace string, labels labels.Instance, isWaypoint bool) WorkloadPolicyMatcher {
	return WorkloadPolicyMatcher{
		Namespace:      workloadNamespace,
		WorkloadLabels: labels,
		IsWaypoint:     isWaypoint,
	}
}

func PolicyMatcherForProxy(proxy *Proxy) WorkloadPolicyMatcher {
	return WorkloadPolicyMatcher{
		Namespace:      proxy.ConfigNamespace,
		WorkloadLabels: proxy.Labels,
		IsWaypoint:     proxy.IsWaypointProxy(),
	}
}

func (p WorkloadPolicyMatcher) WithService(service *Service) WorkloadPolicyMatcher {
	if service == nil {
		return p
	}
	if service.Attributes.Namespace != p.Namespace {
		log.Debugf("matching policy for service in namespace %s for workload in %s", service.Attributes.Namespace, p.Namespace)
	}

	p.Service = service.Attributes.Name
	return p
}

// workloadGatewayName returns the name of the gateway for which a workload is an instance.
// This is based on the gateway.networking.k8s.io/gateway-name label.
func workloadGatewayName(l labels.Instance) (string, bool) {
	gwName, exists := l[constants.GatewayNameLabel]
	if !exists {
		// TODO: Remove deprecated gateway name label (1.22 or 1.23)
		gwName, exists = l[constants.DeprecatedGatewayNameLabel]
	}

	return gwName, exists
}

func (p WorkloadPolicyMatcher) isSelected(policy TargetablePolicy) bool {
	selector := policy.GetSelector()
	return selector == nil || labels.Instance(selector.GetMatchLabels()).SubsetOf(p.WorkloadLabels)
}

// GetTargetRefs returns the list of targetRefs, taking into account the legacy targetRef
func GetTargetRefs(p TargetablePolicy) []*v1beta1.PolicyTargetReference {
	targetRefs := p.GetTargetRefs()
	if len(targetRefs) == 0 && p.GetTargetRef() != nil {
		targetRefs = []*v1beta1.PolicyTargetReference{p.GetTargetRef()}
	}
	return targetRefs
}

func (p WorkloadPolicyMatcher) ShouldAttachPolicy(kind config.GroupVersionKind, policyName types.NamespacedName, policy TargetablePolicy) bool {
	gatewayName, isGatewayAPI := workloadGatewayName(p.WorkloadLabels)
	targetRefs := GetTargetRefs(policy)

	// non-gateway: use selector
	if !isGatewayAPI {
		// if targetRef is specified, ignore the policy altogether
		if len(targetRefs) > 0 {
			return false
		}
		return p.isSelected(policy)
	}

	// gateway with no targetRefs: (sometimes) fallback to selector
	if len(targetRefs) == 0 {
		// gateways require the feature flag for selector-based policy
		// waypoints never use selector
		if p.IsWaypoint || !features.EnableSelectorBasedK8sGatewayPolicy {
			log.Debugf("Ignoring workload-scoped %s/%s %s for gateway %s.%s because it has no targetRef", kind.Group, kind.Kind, policyName, gatewayName, p.Namespace)
			return false
		}
		return p.isSelected(policy)
	}

	for _, targetRef := range targetRefs {
		target := types.NamespacedName{
			Name:      targetRef.GetName(),
			Namespace: GetOrDefault(targetRef.GetNamespace(), policyName.Namespace),
		}

		// Gateway attached
		if config.CanonicalGroup(targetRef.GetGroup()) == gvk.KubernetesGateway.CanonicalGroup() &&
			targetRef.GetKind() == gvk.KubernetesGateway.Kind &&
			target.Name == gatewayName &&
			(targetRef.GetNamespace() == "" || targetRef.GetNamespace() == p.Namespace) {
			return true
		}

		// Service attached
		if p.IsWaypoint &&
			config.CanonicalGroup(targetRef.GetGroup()) == gvk.Service.CanonicalGroup() &&
			targetRef.GetKind() == gvk.Service.Kind &&
			targetRef.GetName() == p.Service &&
			(targetRef.GetNamespace() == "" || targetRef.GetNamespace() == p.Namespace) {
			return true
		}
	}

	return false
}
