package handler

import (
	"net/http"

	"kmesh.net/kmesh-dashboard/backend/internal/auth"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	gatewayapiclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
)

const apiPrefix = "/api"

// Register 注册所有 HTTP 路由（含认证相关）
func Register(mux *http.ServeMux, clientset kubernetes.Interface, gwClient gatewayapiclient.Interface, dyn dynamic.Interface) {
	// 认证：登录与当前用户（/api/auth/login 不需鉴权，由中间件放行）
	mux.HandleFunc(apiPrefix+"/auth/login", auth.Login())
	mux.HandleFunc(apiPrefix+"/auth/me", auth.Me())
	mux.HandleFunc(apiPrefix+"/cluster/nodes", ClusterNodes(clientset))
	mux.HandleFunc(apiPrefix+"/services", ServiceList(clientset))
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
	mux.HandleFunc(apiPrefix+"/waypoint/status", WaypointStatus(gwClient))
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
	// 站内文档：列表与 Markdown 内容
	mux.HandleFunc(apiPrefix+"/docs", Docs())
	mux.HandleFunc(apiPrefix+"/docs/", Docs())
}
