package handler

import (
	"net/http"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	gatewayapiclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
)

const apiPrefix = "/api"

// Register 注册所有 HTTP 路由（含认证相关）
func Register(mux *http.ServeMux, clientset kubernetes.Interface, gwClient gatewayapiclient.Interface, dyn dynamic.Interface) {
	mux.HandleFunc(apiPrefix+"/cluster/nodes", ClusterNodes(clientset))
	mux.HandleFunc(apiPrefix+"/cluster/namespaces", NamespaceList(clientset))
	mux.HandleFunc(apiPrefix+"/services", ServiceList(clientset))
	// 通用 Pod 接口：详情（含 Events）、日志，供 Waypoint 等模块复用
	mux.HandleFunc(apiPrefix+"/pod/detail", PodDetail(clientset))
	mux.HandleFunc(apiPrefix+"/pod/logs", PodLogs(clientset))
	mux.HandleFunc(apiPrefix+"/metrics/datasource", MetricsDatasource())
	mux.HandleFunc(apiPrefix+"/metrics/overview", MetricsOverview())
	mux.HandleFunc(apiPrefix+"/metrics/accesslog", AccesslogList(clientset))
	mux.HandleFunc(apiPrefix+"/metrics/kmesh-pods", KmeshPodsList(clientset))
	mux.HandleFunc(apiPrefix+"/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	// Waypoint
	mux.HandleFunc(apiPrefix+"/waypoint/list", WaypointList(gwClient))
	mux.HandleFunc(apiPrefix+"/waypoint/status", WaypointStatus(gwClient, clientset))
	mux.HandleFunc(apiPrefix+"/waypoint/apply", WaypointApply(gwClient, clientset))
	mux.HandleFunc(apiPrefix+"/waypoint/delete", WaypointDelete(gwClient))
	// 熔断 (DestinationRule，作用于 Waypoint)
	mux.HandleFunc(apiPrefix+"/circuitbreaker/list", CircuitBreakerList(dyn))
	mux.HandleFunc(apiPrefix+"/circuitbreaker/apply", CircuitBreakerApply(dyn, gwClient))
	mux.HandleFunc(apiPrefix+"/circuitbreaker/delete", CircuitBreakerDelete(dyn))
	// 认证策略 (AuthorizationPolicy)
	mux.HandleFunc(apiPrefix+"/authorization/list", AuthorizationPolicyList(dyn))
	mux.HandleFunc(apiPrefix+"/authorization/apply", AuthorizationPolicyApply(dyn))
	mux.HandleFunc(apiPrefix+"/authorization/delete", AuthorizationPolicyDelete(dyn))
	// 限流 (EnvoyFilter local_ratelimit，作用于 Waypoint)
	mux.HandleFunc(apiPrefix+"/ratelimit/list", RateLimitList(dyn))
	mux.HandleFunc(apiPrefix+"/ratelimit/apply", RateLimitApply(dyn, gwClient))
	mux.HandleFunc(apiPrefix+"/ratelimit/delete", RateLimitDelete(dyn))
	// Kiali 配置：返回 KIALI_URL，供拓扑页跳转
	mux.HandleFunc(apiPrefix+"/config", Config())
	// 自定义 YAML 一键应用（各模块通用，含校验器）
	mux.HandleFunc(apiPrefix+"/custom/template", CustomYamlTemplate())
	mux.HandleFunc(apiPrefix+"/custom/validate", CustomYamlValidate())
	mux.HandleFunc(apiPrefix+"/custom/apply", CustomYamlApply(dyn))
	// 站内文档：列表与 Markdown 内容
	mux.HandleFunc(apiPrefix+"/docs", Docs())
	mux.HandleFunc(apiPrefix+"/docs/", Docs())
}
