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
)

var authorizationPolicyGVR = schema.GroupVersionResource{
	Group: "security.istio.io", Version: "v1beta1", Resource: "authorizationpolicies",
}

// AuthorizationPolicyItem 授权策略列表项
type AuthorizationPolicyItem struct {
	Namespace   string                         `json:"namespace"`
	Name        string                         `json:"name"`
	Action      string                         `json:"action"`
	Selector    map[string]string              `json:"selector,omitempty"`
	RulesCount  int                            `json:"rulesCount"`
	WorkloadRef string                         `json:"workloadRef,omitempty"`
	Rules       []AuthorizationPolicyRuleApply `json:"rules,omitempty"`
}

// AuthorizationPolicyListResponse 列表响应
type AuthorizationPolicyListResponse struct {
	Items []AuthorizationPolicyItem `json:"items"`
}

// AuthorizationPolicyApplyRequest 创建/更新请求
type AuthorizationPolicyApplyRequest struct {
	Namespace string                         `json:"namespace"`
	Name      string                         `json:"name"`
	Action    string                         `json:"action"`
	Selector  map[string]string              `json:"selector,omitempty"`
	Rules     []AuthorizationPolicyRuleApply `json:"rules,omitempty"`
}

// AuthorizationPolicyRuleApply 单条规则
type AuthorizationPolicyRuleApply struct {
	From []AuthorizationPolicyFrom `json:"from,omitempty"`
	To   []AuthorizationPolicyTo   `json:"to,omitempty"`
}

// AuthorizationPolicyFrom 来源条件
type AuthorizationPolicyFrom struct {
	Source *AuthorizationPolicySource `json:"source,omitempty"`
}

// AuthorizationPolicySource 来源
type AuthorizationPolicySource struct {
	IPBlocks   []string `json:"ipBlocks,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"`
	Principals []string `json:"principals,omitempty"`
}

// AuthorizationPolicyTo 目标操作
type AuthorizationPolicyTo struct {
	Operation *AuthorizationPolicyOperation `json:"operation,omitempty"`
}

// AuthorizationPolicyOperation 操作条件
type AuthorizationPolicyOperation struct {
	Hosts   []string `json:"hosts,omitempty"`
	Ports   []string `json:"ports,omitempty"`
	Paths   []string `json:"paths,omitempty"`
	Methods []string `json:"methods,omitempty"`
}

// AuthorizationPolicyApplyResponse 应用响应
type AuthorizationPolicyApplyResponse struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Message   string `json:"message"`
}

// AuthorizationPolicyDeleteRequest 删除请求
type AuthorizationPolicyDeleteRequest struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

func toStringSlice(arr []interface{}) []string {
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func extractRulesFromCRD(rulesInterface []interface{}) []AuthorizationPolicyRuleApply {
	var result []AuthorizationPolicyRuleApply
	for _, r := range rulesInterface {
		ruleMap, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		ruleApply := AuthorizationPolicyRuleApply{}

		// 解析 from
		if fromList, ok := ruleMap["from"].([]interface{}); ok {
			for _, f := range fromList {
				fromMap, ok := f.(map[string]interface{})
				if !ok {
					continue
				}
				if src, ok := fromMap["source"].(map[string]interface{}); ok {
					source := &AuthorizationPolicySource{}
					if v, ok := src["ipBlocks"].([]interface{}); ok {
						source.IPBlocks = toStringSlice(v)
					}
					if v, ok := src["namespaces"].([]interface{}); ok {
						source.Namespaces = toStringSlice(v)
					}
					if v, ok := src["principals"].([]interface{}); ok {
						source.Principals = toStringSlice(v)
					}
					if source.IPBlocks != nil || source.Namespaces != nil || source.Principals != nil {
						ruleApply.From = append(ruleApply.From, AuthorizationPolicyFrom{Source: source})
					}
				}
			}
		}

		// 解析 to
		if toList, ok := ruleMap["to"].([]interface{}); ok {
			for _, t := range toList {
				toMap, ok := t.(map[string]interface{})
				if !ok {
					continue
				}
				if op, ok := toMap["operation"].(map[string]interface{}); ok {
					operation := &AuthorizationPolicyOperation{}
					if v, ok := op["hosts"].([]interface{}); ok {
						operation.Hosts = toStringSlice(v)
					}
					if v, ok := op["ports"].([]interface{}); ok {
						// Istio CRD 中 ports 可能是 string 或 int
						for _, p := range v {
							switch x := p.(type) {
							case string:
								operation.Ports = append(operation.Ports, x)
							case int:
								operation.Ports = append(operation.Ports, itoa(x))
							case int64:
								operation.Ports = append(operation.Ports, itoa(int(x)))
							case float64:
								operation.Ports = append(operation.Ports, itoa(int(x)))
							}
						}
					}
					if v, ok := op["paths"].([]interface{}); ok {
						operation.Paths = toStringSlice(v)
					}
					if v, ok := op["methods"].([]interface{}); ok {
						operation.Methods = toStringSlice(v)
					}
					if len(operation.Hosts) > 0 || len(operation.Ports) > 0 || len(operation.Paths) > 0 || len(operation.Methods) > 0 {
						ruleApply.To = append(ruleApply.To, AuthorizationPolicyTo{Operation: operation})
					}
				}
			}
		}

		// 保留所有规则，空规则（无 from/to）表示「匹配全部」
		result = append(result, ruleApply)
	}
	return result
}

func extractAuthorizationPolicyFromCRD(u *unstructured.Unstructured) (item AuthorizationPolicyItem) {
	item.Namespace = u.GetNamespace()
	item.Name = u.GetName()
	spec, ok := u.Object["spec"].(map[string]interface{})
	if !ok {
		return item
	}
	if action, ok := spec["action"].(string); ok {
		item.Action = action
	}
	if sel, ok := spec["selector"].(map[string]interface{}); ok {
		if ml, ok := sel["matchLabels"].(map[string]interface{}); ok {
			item.Selector = make(map[string]string)
			for k, v := range ml {
				if s, ok := v.(string); ok {
					item.Selector[k] = s
				}
			}
			if app, ok := item.Selector["app"]; ok {
				item.WorkloadRef = app
			}
		}
	}
	if rules, ok := spec["rules"].([]interface{}); ok {
		item.RulesCount = len(rules)
		item.Rules = extractRulesFromCRD(rules)
	}
	return item
}

func buildAuthorizationPolicy(req AuthorizationPolicyApplyRequest) *unstructured.Unstructured {
	spec := map[string]interface{}{}
	if req.Action != "" {
		spec["action"] = req.Action
	}
	if len(req.Selector) > 0 {
		spec["selector"] = map[string]interface{}{
			"matchLabels": req.Selector,
		}
	}
	if len(req.Rules) > 0 {
		rules := make([]interface{}, 0, len(req.Rules))
		for _, r := range req.Rules {
			rule := map[string]interface{}{}
			if len(r.From) > 0 {
				fromList := make([]interface{}, 0, len(r.From))
				for _, f := range r.From {
					fromItem := map[string]interface{}{}
					if f.Source != nil {
						src := map[string]interface{}{}
						if len(f.Source.IPBlocks) > 0 {
							src["ipBlocks"] = f.Source.IPBlocks
						}
						if len(f.Source.Namespaces) > 0 {
							src["namespaces"] = f.Source.Namespaces
						}
						if len(f.Source.Principals) > 0 {
							src["principals"] = f.Source.Principals
						}
						if len(src) > 0 {
							fromItem["source"] = src
							fromList = append(fromList, fromItem)
						}
					}
				}
				if len(fromList) > 0 {
					rule["from"] = fromList
				}
			}
			if len(r.To) > 0 {
				toList := make([]interface{}, 0, len(r.To))
				for _, t := range r.To {
					if t.Operation != nil {
						op := map[string]interface{}{}
						if len(t.Operation.Hosts) > 0 {
							op["hosts"] = t.Operation.Hosts
						}
						if len(t.Operation.Ports) > 0 {
							op["ports"] = t.Operation.Ports
						}
						if len(t.Operation.Paths) > 0 {
							op["paths"] = t.Operation.Paths
						}
						if len(t.Operation.Methods) > 0 {
							op["methods"] = t.Operation.Methods
						}
						if len(op) > 0 {
							toList = append(toList, map[string]interface{}{"operation": op})
						}
					}
				}
				if len(toList) > 0 {
					rule["to"] = toList
				}
			}
			if len(rule) > 0 {
				rules = append(rules, rule)
			}
		}
		if len(rules) > 0 {
			spec["rules"] = rules
		}
	}
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "security.istio.io/v1beta1",
			"kind":       "AuthorizationPolicy",
			"metadata": map[string]interface{}{
				"name":      req.Name,
				"namespace": req.Namespace,
			},
			"spec": spec,
		},
	}
}

// AuthorizationPolicyList 列出 AuthorizationPolicy
func AuthorizationPolicyList(dyn dynamic.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ns := r.URL.Query().Get("namespace")
		if ns == "" {
			ns = metav1.NamespaceAll
		}
		list, err := dyn.Resource(authorizationPolicyGVR).Namespace(ns).List(r.Context(), metav1.ListOptions{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var items []AuthorizationPolicyItem
		for _, u := range list.Items {
			items = append(items, extractAuthorizationPolicyFromCRD(&u))
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].Namespace != items[j].Namespace {
				return items[i].Namespace < items[j].Namespace
			}
			return items[i].Name < items[j].Name
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuthorizationPolicyListResponse{Items: items})
	}
}

// AuthorizationPolicyApply 创建或更新 AuthorizationPolicy
func AuthorizationPolicyApply(dyn dynamic.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req AuthorizationPolicyApplyRequest
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
		ap := buildAuthorizationPolicy(req)
		_, err := dyn.Resource(authorizationPolicyGVR).Namespace(req.Namespace).Create(r.Context(), ap, metav1.CreateOptions{FieldManager: "kmesh-dashboard"})
		if err != nil {
			if errors.IsAlreadyExists(err) {
				existing, getErr := dyn.Resource(authorizationPolicyGVR).Namespace(req.Namespace).Get(r.Context(), req.Name, metav1.GetOptions{})
				if getErr != nil {
					http.Error(w, getErr.Error(), http.StatusInternalServerError)
					return
				}
				ap.SetResourceVersion(existing.GetResourceVersion())
				_, err = dyn.Resource(authorizationPolicyGVR).Namespace(req.Namespace).Update(r.Context(), ap, metav1.UpdateOptions{FieldManager: "kmesh-dashboard"})
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuthorizationPolicyApplyResponse{
			Namespace: req.Namespace,
			Name:      req.Name,
			Message:   "授权策略 " + req.Namespace + "/" + req.Name + " 已应用",
		})
	}
}

// AuthorizationPolicyDelete 删除 AuthorizationPolicy
func AuthorizationPolicyDelete(dyn dynamic.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req AuthorizationPolicyDeleteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Namespace == "" || req.Name == "" {
			http.Error(w, "namespace and name are required", http.StatusBadRequest)
			return
		}
		if err := dyn.Resource(authorizationPolicyGVR).Namespace(req.Namespace).Delete(r.Context(), req.Name, metav1.DeleteOptions{}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "已删除"})
	}
}
