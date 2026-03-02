package handler

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	gatewayapiclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
)

var envoyFilterGVR = schema.GroupVersionResource{
	Group: "networking.istio.io", Version: "v1alpha3", Resource: "envoyfilters",
}

const localRateLimitFilterName = "envoy.filters.network.local_ratelimit"

// RateLimitItem 限流策略列表项
type RateLimitItem struct {
	Namespace        string            `json:"namespace"`
	Name             string            `json:"name"`
	StatPrefix       string            `json:"statPrefix,omitempty"`
	MaxTokens        int64             `json:"maxTokens,omitempty"`
	TokensPerFill    int64             `json:"tokensPerFill,omitempty"`
	FillIntervalSec  int64             `json:"fillIntervalSec,omitempty"`
	WorkloadSelector map[string]string `json:"workloadSelector,omitempty"`
}

// RateLimitListResponse 列表响应
type RateLimitListResponse struct {
	Items []RateLimitItem `json:"items"`
}

// RateLimitApplyRequest 创建/更新请求（Token Bucket 维度）
type RateLimitApplyRequest struct {
	Namespace        string            `json:"namespace"`
	Name             string            `json:"name"`
	StatPrefix       string            `json:"statPrefix,omitempty"`
	MaxTokens        int64             `json:"maxTokens"`
	TokensPerFill    int64             `json:"tokensPerFill"`
	FillIntervalSec  int64             `json:"fillIntervalSec"`
	WorkloadSelector map[string]string `json:"workloadSelector,omitempty"`
}

// RateLimitApplyResponse 应用响应
type RateLimitApplyResponse struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Message   string `json:"message"`
}

// RateLimitDeleteRequest 删除请求
type RateLimitDeleteRequest struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// getPatchValue 从 configPatch 中取出 patch.value（Istio 结构为 configPatches[].patch.value）
func getPatchValue(patchItem interface{}) map[string]interface{} {
	pm, _ := patchItem.(map[string]interface{})
	if pm == nil {
		return nil
	}
	patch, _ := pm["patch"].(map[string]interface{})
	if patch == nil {
		val, _ := pm["value"].(map[string]interface{})
		return val
	}
	val, _ := patch["value"].(map[string]interface{})
	return val
}

func isLocalRateLimitEnvoyFilter(u *unstructured.Unstructured) bool {
	patches, ok, _ := unstructured.NestedSlice(u.Object, "spec", "configPatches")
	if !ok || len(patches) == 0 {
		return false
	}
	for _, p := range patches {
		val := getPatchValue(p)
		if val == nil {
			continue
		}
		if n, _ := val["name"].(string); n == localRateLimitFilterName {
			return true
		}
	}
	return false
}

func extractRateLimitFromEnvoyFilter(u *unstructured.Unstructured) (item RateLimitItem, ok bool) {
	item.Namespace = u.GetNamespace()
	item.Name = u.GetName()
	patches, _, _ := unstructured.NestedSlice(u.Object, "spec", "configPatches")
	for _, p := range patches {
		val := getPatchValue(p)
		if val == nil {
			continue
		}
		if n, _ := val["name"].(string); n != localRateLimitFilterName {
			continue
		}
		item.StatPrefix, _, _ = unstructured.NestedString(val, "stat_prefix")
		tb, _, _ := unstructured.NestedMap(val, "typed_config", "token_bucket")
		if tb == nil {
			tb, _, _ = unstructured.NestedMap(val, "token_bucket")
		}
		if tb != nil {
			if v, ok := tb["max_tokens"].(int64); ok {
				item.MaxTokens = v
			} else if v, ok := tb["max_tokens"].(float64); ok {
				item.MaxTokens = int64(v)
			}
			if v, ok := tb["tokens_per_fill"].(int64); ok {
				item.TokensPerFill = v
			} else if v, ok := tb["tokens_per_fill"].(float64); ok {
				item.TokensPerFill = int64(v)
			}
			if s, ok := tb["fill_interval"].(string); ok && s != "" {
				item.FillIntervalSec = parseFillIntervalSec(s)
			}
		}
		ws, _, _ := unstructured.NestedStringMap(u.Object, "spec", "workloadSelector", "labels")
		if len(ws) > 0 {
			item.WorkloadSelector = ws
		}
		return item, true
	}
	return item, false
}

func parseFillIntervalSec(s string) int64 {
	// "60s" -> 60, "1m" -> 60
	var num int64
	for _, c := range s {
		if c >= '0' && c <= '9' {
			num = num*10 + int64(c-'0')
		} else {
			break
		}
	}
	if len(s) > 0 && s[len(s)-1] == 's' {
		return num
	}
	if len(s) > 0 && s[len(s)-1] == 'm' {
		return num * 60
	}
	return num
}

func buildLocalRateLimitEnvoyFilter(req RateLimitApplyRequest) *unstructured.Unstructured {
	statPrefix := req.StatPrefix
	if statPrefix == "" {
		statPrefix = "local_rate_limit"
	}
	fillInterval := strconv.FormatInt(req.FillIntervalSec, 10) + "s"
	if req.FillIntervalSec <= 0 {
		req.FillIntervalSec = 60
		fillInterval = "60s"
	}
	if req.MaxTokens <= 0 {
		req.MaxTokens = 4
	}
	if req.TokensPerFill <= 0 {
		req.TokensPerFill = 4
	}
	value := map[string]interface{}{
		"name": localRateLimitFilterName,
		"typed_config": map[string]interface{}{
			"@type":       "type.googleapis.com/envoy.extensions.filters.network.local_ratelimit.v3.LocalRateLimit",
			"stat_prefix": statPrefix,
			"token_bucket": map[string]interface{}{
				"max_tokens":       req.MaxTokens,
				"tokens_per_fill":  req.TokensPerFill,
				"fill_interval":    fillInterval,
			},
		},
	}
	spec := map[string]interface{}{
		"configPatches": []interface{}{
			map[string]interface{}{
				"applyTo": "NETWORK_FILTER",
				"match": map[string]interface{}{
					"listener": map[string]interface{}{
						"filterChain": map[string]interface{}{
							"filter": map[string]interface{}{
								"name": "envoy.filters.network.tcp_proxy",
							},
						},
					},
				},
				"patch": map[string]interface{}{
					"operation": "INSERT_BEFORE",
					"value":    value,
				},
			},
		},
	}
	if len(req.WorkloadSelector) > 0 {
		spec["workloadSelector"] = map[string]interface{}{"labels": req.WorkloadSelector}
	}
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.istio.io/v1alpha3",
			"kind":       "EnvoyFilter",
			"metadata": map[string]interface{}{
				"name":      req.Name,
				"namespace": req.Namespace,
			},
			"spec": spec,
		},
	}
}

// RateLimitList 列出含 local_ratelimit 的 EnvoyFilter
func RateLimitList(dyn dynamic.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ns := r.URL.Query().Get("namespace")
		if ns == "" {
			ns = metav1.NamespaceAll
		}
		list, err := dyn.Resource(envoyFilterGVR).Namespace(ns).List(r.Context(), metav1.ListOptions{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var items []RateLimitItem
		for _, u := range list.Items {
			if !isLocalRateLimitEnvoyFilter(&u) {
				continue
			}
			item, ok := extractRateLimitFromEnvoyFilter(&u)
			if ok {
				items = append(items, item)
			}
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].Namespace != items[j].Namespace {
				return items[i].Namespace < items[j].Namespace
			}
			return items[i].Name < items[j].Name
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(RateLimitListResponse{Items: items})
	}
}

// RateLimitApply 创建或更新限流 EnvoyFilter（限流作用于 Waypoint）
func RateLimitApply(dyn dynamic.Interface, gwClient gatewayapiclient.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req RateLimitApplyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Namespace == "" {
			req.Namespace = "default"
		}
		if req.Name == "" {
			http.Error(w, "name is required", http.StatusBadRequest)
			return
		}
		// 限流作用于 Waypoint，下发前需确保命名空间已安装 Waypoint
		hasWaypoint, err := HasWaypointInNamespace(r.Context(), gwClient, req.Namespace)
		if err != nil {
			http.Error(w, "检查 Waypoint 状态失败: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if !hasWaypoint {
			http.Error(w, "限流策略作用于 Waypoint，请先在命名空间 "+req.Namespace+" 安装 Waypoint", http.StatusPreconditionFailed)
			return
		}
		ef := buildLocalRateLimitEnvoyFilter(req)
		_, err = dyn.Resource(envoyFilterGVR).Namespace(req.Namespace).Create(r.Context(), ef, metav1.CreateOptions{FieldManager: "kmesh-dashboard"})
		if err != nil {
			if errors.IsAlreadyExists(err) {
				existing, getErr := dyn.Resource(envoyFilterGVR).Namespace(req.Namespace).Get(r.Context(), req.Name, metav1.GetOptions{})
				if getErr != nil {
					http.Error(w, getErr.Error(), http.StatusInternalServerError)
					return
				}
				ef.SetResourceVersion(existing.GetResourceVersion())
				_, err = dyn.Resource(envoyFilterGVR).Namespace(req.Namespace).Update(r.Context(), ef, metav1.UpdateOptions{FieldManager: "kmesh-dashboard"})
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(RateLimitApplyResponse{
			Namespace: req.Namespace,
			Name:      req.Name,
			Message:   "限流策略 " + req.Namespace + "/" + req.Name + " 已下发",
		})
	}
}

// RateLimitDelete 删除限流 EnvoyFilter
func RateLimitDelete(dyn dynamic.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req RateLimitDeleteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Namespace == "" || req.Name == "" {
			http.Error(w, "namespace and name are required", http.StatusBadRequest)
			return
		}
		if err := dyn.Resource(envoyFilterGVR).Namespace(req.Namespace).Delete(r.Context(), req.Name, metav1.DeleteOptions{}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "已删除"})
	}
}
