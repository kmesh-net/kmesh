package handler

import (
	"encoding/json"
	"net/http"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ServiceItem 服务简要信息，用于前端选择目标 Host
type ServiceItem struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// ServiceListResponse 服务列表响应
type ServiceListResponse struct {
	Items []ServiceItem `json:"items"`
}

// ServiceList 列出集群中的 Service（用于熔断等场景选择目标 Host）
// Query: namespace（空则全部命名空间）
func ServiceList(clientset kubernetes.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ns := r.URL.Query().Get("namespace")
		if ns == "" {
			ns = metav1.NamespaceAll
		}
		list, err := clientset.CoreV1().Services(ns).List(r.Context(), metav1.ListOptions{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		items := make([]ServiceItem, 0, len(list.Items))
		for _, svc := range list.Items {
			items = append(items, ServiceItem{Namespace: svc.Namespace, Name: svc.Name})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ServiceListResponse{Items: items})
	}
}
