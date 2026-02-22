package handler

import (
	"net/http"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	gatewayapiclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
)

const apiPrefix = "/api"

// Register 注册所有 HTTP 路由
func Register(mux *http.ServeMux, clientset kubernetes.Interface, gwClient gatewayapiclient.Interface, dyn dynamic.Interface) {
	mux.HandleFunc(apiPrefix+"/cluster/nodes", ClusterNodes(clientset))
	mux.HandleFunc(apiPrefix+"/services", ServiceList(clientset))
	mux.HandleFunc(apiPrefix+"/metrics/datasource", MetricsDatasource())
	mux.HandleFunc(apiPrefix+"/metrics/overview", MetricsOverview())
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
	mux.HandleFunc(apiPrefix+"/waypoint/apply", WaypointApply(gwClient))
	mux.HandleFunc(apiPrefix+"/waypoint/delete", WaypointDelete(gwClient))
	// 熔断 (DestinationRule)
	mux.HandleFunc(apiPrefix+"/circuitbreaker/list", CircuitBreakerList(dyn))
	mux.HandleFunc(apiPrefix+"/circuitbreaker/apply", CircuitBreakerApply(dyn))
	mux.HandleFunc(apiPrefix+"/circuitbreaker/delete", CircuitBreakerDelete(dyn))
	// 限流 (EnvoyFilter local_ratelimit)
	mux.HandleFunc(apiPrefix+"/ratelimit/list", RateLimitList(dyn))
	mux.HandleFunc(apiPrefix+"/ratelimit/apply", RateLimitApply(dyn))
	mux.HandleFunc(apiPrefix+"/ratelimit/delete", RateLimitDelete(dyn))
}
