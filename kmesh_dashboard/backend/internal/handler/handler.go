package handler

import (
	"net/http"

	"k8s.io/client-go/kubernetes"
)

const apiPrefix = "/api"

// Register 注册所有 HTTP 路由
func Register(mux *http.ServeMux, clientset kubernetes.Interface) {
	mux.HandleFunc(apiPrefix+"/cluster/nodes", ClusterNodes(clientset))
	mux.HandleFunc(apiPrefix+"/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
}
