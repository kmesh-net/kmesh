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

package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"sigs.k8s.io/yaml"
)

// ModuleConfig 各模块的 YAML 校验与应用配置
type ModuleConfig struct {
	Module      string // circuitbreaker, ratelimit, authorization, waypoint
	APIVersion  string
	Kind        string
	GVR         schema.GroupVersionResource
	DefaultYAML string
}

var moduleConfigs = map[string]ModuleConfig{
	"circuitbreaker": {
		Module:     "circuitbreaker",
		APIVersion: "networking.istio.io/v1beta1",
		Kind:       "DestinationRule",
		GVR:        schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1beta1", Resource: "destinationrules"},
		DefaultYAML: `apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: example-cb
  namespace: default
spec:
  host: reviews.default.svc.cluster.local
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 100
      http:
        http1MaxPendingRequests: 50
        http2MaxRequests: 2
        maxRetries: 3
`,
	},
	"ratelimit": {
		Module:     "ratelimit",
		APIVersion: "networking.istio.io/v1alpha3",
		Kind:       "EnvoyFilter",
		GVR:        schema.GroupVersionResource{Group: "networking.istio.io", Version: "v1alpha3", Resource: "envoyfilters"},
		DefaultYAML: `apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: example-ratelimit
  namespace: default
spec:
  workloadSelector:
    labels:
      app: reviews
  configPatches:
  - applyTo: NETWORK_FILTER
    match:
      listener:
        filterChain:
          filter:
            name: envoy.filters.network.tcp_proxy
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.filters.network.local_ratelimit
        typed_config:
          "@type": "type.googleapis.com/envoy.extensions.filters.network.local_ratelimit.v3.LocalRateLimit"
          stat_prefix: local_rate_limit
          token_bucket:
            max_tokens: 100
            tokens_per_fill: 10
            fill_interval: 60s
`,
	},
	"authorization": {
		Module:     "authorization",
		APIVersion: "security.istio.io/v1beta1",
		Kind:       "AuthorizationPolicy",
		GVR:        schema.GroupVersionResource{Group: "security.istio.io", Version: "v1beta1", Resource: "authorizationpolicies"},
		DefaultYAML: `apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: example-allow
  namespace: default
spec:
  action: ALLOW
  selector:
    matchLabels:
      app: reviews
  rules:
  - from:
    - source:
        namespaces: ["default"]
    to:
    - operation:
        methods: ["GET"]
`,
	},
	"waypoint": {
		Module:     "waypoint",
		APIVersion: "gateway.networking.k8s.io/v1",
		Kind:       "Gateway",
		GVR:        schema.GroupVersionResource{Group: "gateway.networking.k8s.io", Version: "v1", Resource: "gateways"},
		DefaultYAML: `apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: waypoint
  namespace: default
  labels:
    istio.io/waypoint-for: service
  annotations:
    sidecar.istio.io/proxyImage: ghcr.io/kmesh-net/waypoint:latest
spec:
  gatewayClassName: istio-waypoint
  listeners:
  - name: mesh
    port: 15008
    protocol: HBONE
`,
	},
}

// CustomYamlApplyRequest 自定义 YAML 应用请求
type CustomYamlApplyRequest struct {
	Module    string `json:"module"`    // circuitbreaker, ratelimit, authorization, waypoint
	Namespace string `json:"namespace"`
	YAML      string `json:"yaml"`
}

// CustomYamlApplyResponse 应用响应
type CustomYamlApplyResponse struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Message   string `json:"message"`
	Error     string `json:"error,omitempty"`
}

// CustomYamlTemplateResponse 获取模块默认模板
type CustomYamlTemplateResponse struct {
	Module   string `json:"module"`
	YAML     string `json:"yaml"`
	APIVersion string `json:"apiVersion"`
	Kind     string `json:"kind"`
}

// CustomYamlValidateRequest 校验请求
type CustomYamlValidateRequest struct {
	Module string `json:"module"`
	YAML   string `json:"yaml"`
}

// CustomYamlValidateResponse 校验响应
type CustomYamlValidateResponse struct {
	Valid  bool   `json:"valid"`
	Error  string `json:"error,omitempty"`
	Name   string `json:"name,omitempty"`
	Kind   string `json:"kind,omitempty"`
}

// CustomYamlTemplate 获取模块默认 YAML 模板
func CustomYamlTemplate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		module := r.URL.Query().Get("module")
		if module == "" {
			http.Error(w, "module is required", http.StatusBadRequest)
			return
		}
		cfg, ok := moduleConfigs[module]
		if !ok {
			http.Error(w, "unknown module: "+module, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(CustomYamlTemplateResponse{
			Module:     cfg.Module,
			YAML:       cfg.DefaultYAML,
			APIVersion: cfg.APIVersion,
			Kind:       cfg.Kind,
		})
	}
}

// CustomYamlValidate 校验 YAML 格式与 kind 是否匹配模块
func CustomYamlValidate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req CustomYamlValidateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
			return
		}
		cfg, ok := moduleConfigs[req.Module]
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(CustomYamlValidateResponse{Valid: false, Error: "unknown module: " + req.Module})
			return
		}
		resp := validateYamlForModule(req.YAML, cfg)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func validateYamlForModule(yamlStr string, cfg ModuleConfig) CustomYamlValidateResponse {
	yamlStr = strings.TrimSpace(yamlStr)
	if yamlStr == "" {
		return CustomYamlValidateResponse{Valid: false, Error: "YAML 不能为空"}
	}
	var obj map[string]interface{}
	if err := yaml.Unmarshal([]byte(yamlStr), &obj); err != nil {
		return CustomYamlValidateResponse{Valid: false, Error: "YAML 解析失败: " + err.Error()}
	}
	apiVersion, _ := obj["apiVersion"].(string)
	kind, _ := obj["kind"].(string)
	if apiVersion == "" {
		return CustomYamlValidateResponse{Valid: false, Error: "缺少 apiVersion"}
	}
	if kind == "" {
		return CustomYamlValidateResponse{Valid: false, Error: "缺少 kind"}
	}
	if kind != cfg.Kind {
		return CustomYamlValidateResponse{
			Valid: false,
			Error: "kind 必须为 " + cfg.Kind + "，当前为 " + kind,
			Kind:  kind,
		}
	}
	meta, ok := obj["metadata"].(map[string]interface{})
	if !ok {
		return CustomYamlValidateResponse{Valid: false, Error: "缺少 metadata"}
	}
	name, _ := meta["name"].(string)
	if name == "" {
		return CustomYamlValidateResponse{Valid: false, Error: "metadata.name 不能为空"}
	}
	return CustomYamlValidateResponse{Valid: true, Name: name, Kind: kind}
}

// CustomYamlApply 解析、校验并应用自定义 YAML 到集群
func CustomYamlApply(dyn dynamic.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req CustomYamlApplyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
			return
		}
		req.Module = strings.TrimSpace(req.Module)
		req.Namespace = strings.TrimSpace(req.Namespace)
		req.YAML = strings.TrimSpace(req.YAML)
		if req.Module == "" {
			http.Error(w, "module is required", http.StatusBadRequest)
			return
		}
		if req.Namespace == "" {
			req.Namespace = "default"
		}
		if req.YAML == "" {
			http.Error(w, "yaml is required", http.StatusBadRequest)
			return
		}

		cfg, ok := moduleConfigs[req.Module]
		if !ok {
			http.Error(w, "unknown module: "+req.Module, http.StatusBadRequest)
			return
		}

		validateResp := validateYamlForModule(req.YAML, cfg)
		if !validateResp.Valid {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(CustomYamlApplyResponse{
				Namespace: req.Namespace,
				Message:   validateResp.Error,
				Error:     validateResp.Error,
			})
			return
		}

		var unstructuredObj unstructured.Unstructured
		if err := yaml.Unmarshal([]byte(req.YAML), &unstructuredObj.Object); err != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(CustomYamlApplyResponse{
				Namespace: req.Namespace,
				Name:      validateResp.Name,
				Error:     "YAML 解析失败: " + err.Error(),
			})
			return
		}
		unstructuredObj.SetNamespace(req.Namespace)

		_, err := dyn.Resource(cfg.GVR).Namespace(req.Namespace).Create(r.Context(), &unstructuredObj, metav1.CreateOptions{FieldManager: "kmesh-dashboard"})
		if err != nil {
			if errors.IsAlreadyExists(err) {
				existing, getErr := dyn.Resource(cfg.GVR).Namespace(req.Namespace).Get(r.Context(), validateResp.Name, metav1.GetOptions{})
				if getErr != nil {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(CustomYamlApplyResponse{
						Namespace: req.Namespace,
						Name:      validateResp.Name,
						Error:     getErr.Error(),
					})
					return
				}
				unstructuredObj.SetResourceVersion(existing.GetResourceVersion())
				_, err = dyn.Resource(cfg.GVR).Namespace(req.Namespace).Update(r.Context(), &unstructuredObj, metav1.UpdateOptions{FieldManager: "kmesh-dashboard"})
			}
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(CustomYamlApplyResponse{
					Namespace: req.Namespace,
					Name:      validateResp.Name,
					Error:     err.Error(),
				})
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(CustomYamlApplyResponse{
			Namespace: req.Namespace,
			Name:      validateResp.Name,
			Message:   "已成功应用到集群",
		})
	}
}
