package handler

import (
	"encoding/json"
	"net/http"
	"sort"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	gatewayapiclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	"kmesh.net/kmesh-dashboard/backend/internal/lang"
)

var destinationRuleGVR = schema.GroupVersionResource{
	Group: "networking.istio.io", Version: "v1beta1", Resource: "destinationrules",
}

// CircuitBreakerItem is a circuit-breaker list item.
type CircuitBreakerItem struct {
	Namespace            string `json:"namespace"`
	Name                 string `json:"name"`
	Host                 string `json:"host"`
	MaxConnections       int32  `json:"maxConnections,omitempty"`
	MaxPendingRequests   int32  `json:"maxPendingRequests,omitempty"`
	MaxRequests          int32  `json:"maxRequests,omitempty"`
	MaxRetries           int32  `json:"maxRetries,omitempty"`
	ConnectTimeoutMs     int32  `json:"connectTimeoutMs,omitempty"`
	MaxRequestsPerConn   int32  `json:"maxRequestsPerConnection,omitempty"`
}

// CircuitBreakerListResponse is the list response payload.
type CircuitBreakerListResponse struct {
	Items []CircuitBreakerItem `json:"items"`
}

// CircuitBreakerApplyRequest is the create/update request (aligned with design fields).
type CircuitBreakerApplyRequest struct {
	Namespace              string `json:"namespace"`
	Name                   string `json:"name"`
	Host                   string `json:"host"`
	MaxConnections         int32  `json:"maxConnections,omitempty"`
	MaxPendingRequests     int32  `json:"maxPendingRequests,omitempty"`
	MaxRequests            int32  `json:"maxRequests,omitempty"`
	MaxRetries             int32  `json:"maxRetries,omitempty"`
	ConnectTimeoutMs       int32  `json:"connectTimeoutMs,omitempty"`
	MaxRequestsPerConn     int32  `json:"maxRequestsPerConnection,omitempty"`
}

// CircuitBreakerApplyResponse is the create/update response payload.
type CircuitBreakerApplyResponse struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Message   string `json:"message"`
}

// CircuitBreakerDeleteRequest is the delete request payload.
type CircuitBreakerDeleteRequest struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func extractCircuitBreakerFromDR(u *unstructured.Unstructured) (item CircuitBreakerItem, hasPolicy bool) {
	item.Namespace = u.GetNamespace()
	item.Name = u.GetName()
	spec, ok := u.Object["spec"].(map[string]interface{})
	if !ok {
		return item, false
	}
	if h, ok := spec["host"].(string); ok {
		item.Host = h
	}
	tp, ok := spec["trafficPolicy"].(map[string]interface{})
	if !ok {
		return item, false
	}
	cp, ok := tp["connectionPool"].(map[string]interface{})
	if !ok {
		return item, false
	}
	hasPolicy = true
	if tcp, ok := cp["tcp"].(map[string]interface{}); ok {
		if v, ok := tcp["maxConnections"].(int64); ok {
			item.MaxConnections = int32(v)
		}
		if s, ok := tcp["connectTimeout"].(string); ok && s != "" {
			item.ConnectTimeoutMs = parseDurationMs(s)
		}
	}
	if http, ok := cp["http"].(map[string]interface{}); ok {
		if v, ok := http["http1MaxPendingRequests"].(int64); ok {
			item.MaxPendingRequests = int32(v)
		}
		if v, ok := http["http2MaxRequests"].(int64); ok {
			item.MaxRequests = int32(v)
		}
		if v, ok := http["maxRetries"].(int64); ok {
			item.MaxRetries = int32(v)
		}
		if v, ok := http["maxRequestsPerConnection"].(int64); ok {
			item.MaxRequestsPerConn = int32(v)
		}
	}
	return item, hasPolicy
}

func parseDurationMs(s string) int32 {
	var n int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			break
		}
	}
	// rest is unit: "ms" or "s"
	if len(s) >= 2 && s[len(s)-2:] == "ms" {
		return int32(n)
	}
	if len(s) >= 1 && s[len(s)-1] == 's' {
		return int32(n) * 1000
	}
	return 0
}

func buildDestinationRule(req CircuitBreakerApplyRequest) *unstructured.Unstructured {
	spec := map[string]interface{}{
		"host": req.Host,
	}
	tcp := map[string]interface{}{}
	http := map[string]interface{}{}
	if req.MaxConnections > 0 {
		tcp["maxConnections"] = req.MaxConnections
	}
	if req.ConnectTimeoutMs > 0 {
		tcp["connectTimeout"] = formatMs(req.ConnectTimeoutMs)
	}
	if req.MaxPendingRequests > 0 {
		http["http1MaxPendingRequests"] = req.MaxPendingRequests
	}
	if req.MaxRequests > 0 {
		http["http2MaxRequests"] = req.MaxRequests
	}
	if req.MaxRetries > 0 {
		http["maxRetries"] = req.MaxRetries
	}
	if req.MaxRequestsPerConn > 0 {
		http["maxRequestsPerConnection"] = req.MaxRequestsPerConn
	}
	if len(tcp) > 0 || len(http) > 0 {
		cp := map[string]interface{}{}
		if len(tcp) > 0 {
			cp["tcp"] = tcp
		}
		if len(http) > 0 {
			cp["http"] = http
		}
		spec["trafficPolicy"] = map[string]interface{}{"connectionPool": cp}
	}
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "networking.istio.io/v1beta1",
			"kind":       "DestinationRule",
			"metadata": map[string]interface{}{
				"name":      req.Name,
				"namespace": req.Namespace,
			},
			"spec": spec,
		},
	}
}

func formatMs(ms int32) string {
	if ms >= 1000 {
		return itoa(int(ms/1000)) + "s"
	}
	return itoa(int(ms)) + "ms"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// CircuitBreakerList lists DestinationRules with connectionPool.
func CircuitBreakerList(dyn dynamic.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ns := r.URL.Query().Get("namespace")
		if ns == "" {
			ns = metav1.NamespaceAll
		}
		drList, err := dyn.Resource(destinationRuleGVR).Namespace(ns).List(r.Context(), metav1.ListOptions{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var items []CircuitBreakerItem
		for _, u := range drList.Items {
			item, has := extractCircuitBreakerFromDR(&u)
			if has {
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
		_ = json.NewEncoder(w).Encode(CircuitBreakerListResponse{Items: items})
	}
}

// CircuitBreakerApply creates or updates DestinationRule (circuit breaker, applied to Waypoint).
func CircuitBreakerApply(dyn dynamic.Interface, gwClient gatewayapiclient.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req CircuitBreakerApplyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Namespace == "" {
			req.Namespace = "default"
		}
		if req.Name == "" || req.Host == "" {
			http.Error(w, "name and host are required", http.StatusBadRequest)
			return
		}
		// Circuit breaker is applied to Waypoint; ensure Waypoint is installed before apply.
		loc := lang.LocaleFromRequest(r)
		hasWaypoint, err := HasWaypointInNamespace(r.Context(), gwClient, req.Namespace)
		if err != nil {
			http.Error(w, lang.Msg(loc, "circuitbreaker.checkFailed", map[string]string{"err": err.Error()}), http.StatusInternalServerError)
			return
		}
		if !hasWaypoint {
			http.Error(w, lang.Msg(loc, "circuitbreaker.needWaypoint", map[string]string{"ns": req.Namespace}), http.StatusPreconditionFailed)
			return
		}
		dr := buildDestinationRule(req)
		_, err = dyn.Resource(destinationRuleGVR).Namespace(req.Namespace).Create(r.Context(), dr, metav1.CreateOptions{FieldManager: "kmesh-dashboard"})
		if err != nil {
			if errors.IsAlreadyExists(err) {
				existing, getErr := dyn.Resource(destinationRuleGVR).Namespace(req.Namespace).Get(r.Context(), req.Name, metav1.GetOptions{})
				if getErr != nil {
					http.Error(w, getErr.Error(), http.StatusInternalServerError)
					return
				}
				dr.SetResourceVersion(existing.GetResourceVersion())
				_, err = dyn.Resource(destinationRuleGVR).Namespace(req.Namespace).Update(r.Context(), dr, metav1.UpdateOptions{FieldManager: "kmesh-dashboard"})
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(CircuitBreakerApplyResponse{
			Namespace: req.Namespace,
			Name:      req.Name,
			Message:   lang.Msg(loc, "circuitbreaker.applySuccess", map[string]string{"ns": req.Namespace, "name": req.Name}),
		})
	}
}

// CircuitBreakerDelete deletes DestinationRule.
func CircuitBreakerDelete(dyn dynamic.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req CircuitBreakerDeleteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Namespace == "" || req.Name == "" {
			http.Error(w, "namespace and name are required", http.StatusBadRequest)
			return
		}
		if err := dyn.Resource(destinationRuleGVR).Namespace(req.Namespace).Delete(r.Context(), req.Name, metav1.DeleteOptions{}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "已删除"})
	}
}
