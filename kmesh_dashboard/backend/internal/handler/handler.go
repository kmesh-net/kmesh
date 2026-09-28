package handler

import (
	"net/http"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	gatewayapiclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
)

const apiPrefix = "/api"

// Register registers all HTTP routes, including auth-related ones.
func Register(mux *http.ServeMux, clientset kubernetes.Interface, gwClient gatewayapiclient.Interface, dyn dynamic.Interface) {
	mux.HandleFunc(apiPrefix+"/cluster/nodes", ClusterNodes(clientset))
	mux.HandleFunc(apiPrefix+"/cluster/namespaces", NamespaceList(clientset))
	mux.HandleFunc(apiPrefix+"/services", ServiceList(clientset))
	// Shared Pod endpoints: details (with Events) and logs, reused by modules like Waypoint.
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
	// Circuit breaker (DestinationRule, applied to Waypoint)
	mux.HandleFunc(apiPrefix+"/circuitbreaker/list", CircuitBreakerList(dyn))
	mux.HandleFunc(apiPrefix+"/circuitbreaker/apply", CircuitBreakerApply(dyn, gwClient))
	mux.HandleFunc(apiPrefix+"/circuitbreaker/delete", CircuitBreakerDelete(dyn))
	// Authorization policy (AuthorizationPolicy)
	mux.HandleFunc(apiPrefix+"/authorization/list", AuthorizationPolicyList(dyn))
	mux.HandleFunc(apiPrefix+"/authorization/apply", AuthorizationPolicyApply(dyn))
	mux.HandleFunc(apiPrefix+"/authorization/delete", AuthorizationPolicyDelete(dyn))
	// Rate limit (EnvoyFilter local_ratelimit, applied to Waypoint)
	mux.HandleFunc(apiPrefix+"/ratelimit/list", RateLimitList(dyn))
	mux.HandleFunc(apiPrefix+"/ratelimit/apply", RateLimitApply(dyn, gwClient))
	mux.HandleFunc(apiPrefix+"/ratelimit/delete", RateLimitDelete(dyn))
	// Kiali config: returns KIALI_URL for topology redirection.
	mux.HandleFunc(apiPrefix+"/config", Config())
	// One-click custom YAML operations (shared by modules, includes validator).
	mux.HandleFunc(apiPrefix+"/custom/template", CustomYamlTemplate())
	mux.HandleFunc(apiPrefix+"/custom/validate", CustomYamlValidate())
	mux.HandleFunc(apiPrefix+"/custom/apply", CustomYamlApply(dyn))
	// In-app docs: list and Markdown content.
	mux.HandleFunc(apiPrefix+"/docs", Docs())
	mux.HandleFunc(apiPrefix+"/docs/", Docs())
}
