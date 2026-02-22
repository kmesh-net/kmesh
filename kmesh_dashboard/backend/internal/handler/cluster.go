package handler

import (
	"encoding/json"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// NodeItem 供前端展示的节点简要信息
type NodeItem struct {
	Name        string            `json:"name"`
	Status      string            `json:"status"`
	Roles       []string          `json:"roles,omitempty"`
	Age         string            `json:"age"`
	Kernel      string            `json:"kernel,omitempty"`
	OSImage     string            `json:"osImage,omitempty"`
	InternalIP  string            `json:"internalIP,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

// ClusterNodesResponse 集群节点列表响应
type ClusterNodesResponse struct {
	Nodes []NodeItem `json:"nodes"`
}

// ClusterNodes 返回当前集群的 Node 列表，用于前端「集群状态」页展示。
func ClusterNodes(clientset kubernetes.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		nodeList, err := clientset.CoreV1().Nodes().List(r.Context(), metav1.ListOptions{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		items := make([]NodeItem, 0, len(nodeList.Items))
		for _, n := range nodeList.Items {
			status := "Unknown"
			for _, c := range n.Status.Conditions {
				if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
					status = "Ready"
					break
				}
			}
			roles := make([]string, 0)
			for k := range n.Labels {
				if k == "node-role.kubernetes.io/control-plane" || k == "node-role.kubernetes.io/master" {
					roles = append(roles, "control-plane")
					break
				}
				if k == "node-role.kubernetes.io/worker" {
					roles = append(roles, "worker")
					break
				}
			}
			if len(roles) == 0 {
				roles = append(roles, "-")
			}
			age := ""
			if !n.CreationTimestamp.IsZero() {
				age = time.Since(n.CreationTimestamp.Time).Round(time.Second).String()
			}
			internalIP := ""
			for _, a := range n.Status.Addresses {
				if a.Type == corev1.NodeInternalIP {
					internalIP = a.Address
					break
				}
			}
			kernel := n.Status.NodeInfo.KernelVersion
			osImage := n.Status.NodeInfo.OSImage
			items = append(items, NodeItem{
				Name:       n.Name,
				Status:     status,
				Roles:      roles,
				Age:        age,
				Kernel:     kernel,
				OSImage:    osImage,
				InternalIP: internalIP,
				Labels:     n.Labels,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ClusterNodesResponse{Nodes: items})
	}
}
