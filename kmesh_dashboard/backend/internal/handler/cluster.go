package handler

import (
	"encoding/json"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// NodeItem is a compact node view for frontend display.
type NodeItem struct {
	Name       string            `json:"name"`
	Status     string            `json:"status"`
	Roles      []string          `json:"roles,omitempty"`
	Age        string            `json:"age"`
	Kernel     string            `json:"kernel,omitempty"`
	OSImage    string            `json:"osImage,omitempty"`
	InternalIP string            `json:"internalIP,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// ClusterNodesResponse is the response payload for cluster nodes.
type ClusterNodesResponse struct {
	Nodes []NodeItem `json:"nodes"`
}

// ClusterNodes returns the Node list of the current cluster for the cluster status page.
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

// NamespaceListResponse is the response payload for namespace listing.
type NamespaceListResponse struct {
	Items []string `json:"items"`
}

// NamespaceList returns cluster namespaces for module namespace selectors (e.g. Waypoint).
func NamespaceList(clientset kubernetes.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		list, err := clientset.CoreV1().Namespaces().List(r.Context(), metav1.ListOptions{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		items := make([]string, 0, len(list.Items))
		for _, ns := range list.Items {
			items = append(items, ns.Name)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(NamespaceListResponse{Items: items})
	}
}
