package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"time"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapiclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const (
	waypointGatewayClassName = "istio-waypoint"
	labelWaypointFor         = "istio.io/waypoint-for"
	labelUseWaypoint         = "istio.io/use-waypoint"
	labelIstioRev            = "istio.io/rev"
	annotationProxyImage     = "sidecar.istio.io/proxyImage"
	defaultWaypointImage     = "ghcr.io/kmesh-net/waypoint:latest"
	waitReadyTimeout         = 60 * time.Second
	waitReadyPollInterval    = 2 * time.Second
)

// HasWaypointInNamespace 检查命名空间是否已安装 Waypoint（熔断、限流等策略作用于 Waypoint，下发前需确保存在）
func HasWaypointInNamespace(ctx context.Context, gwClient gatewayapiclient.Interface, namespace string) (bool, error) {
	gwList, err := gwClient.GatewayV1().Gateways(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	for _, gw := range gwList.Items {
		if gw.Spec.GatewayClassName == waypointGatewayClassName {
			return true, nil
		}
	}
	return false, nil
}

// WaypointListResponse 列表响应
type WaypointListResponse struct {
	Items []WaypointItem `json:"items"`
}

// WaypointItem 单条 Waypoint 信息
type WaypointItem struct {
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	Revision   string `json:"revision"`
	Programmed string `json:"programmed"`
	TrafficFor string `json:"trafficFor,omitempty"`
	GatewayUID string `json:"gatewayUID,omitempty"`
}

// WaypointStatusResponse 状态响应（含 conditions）
type WaypointStatusResponse struct {
	Items []WaypointStatusItem `json:"items"`
}

// WaypointStatusItem 单条状态
type WaypointStatusItem struct {
	WaypointItem
	Conditions []Condition `json:"conditions,omitempty"`
}

// Condition 与 metav1.Condition 对应
type Condition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// WaypointApplyRequest 安装请求
type WaypointApplyRequest struct {
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	TrafficFor      string `json:"trafficFor"` // service | workload | all | 空表示默认
	EnrollNamespace bool   `json:"enrollNamespace"`
	Overwrite       bool   `json:"overwrite"`
	WaitReady       bool   `json:"waitReady"`
	Revision        string `json:"revision"`
	ProxyImage      string `json:"proxyImage"`
}

// WaypointApplyResponse 安装响应
type WaypointApplyResponse struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Message   string `json:"message"`
}

// WaypointDeleteRequest 删除请求（按名称或全部）
type WaypointDeleteRequest struct {
	Namespace string   `json:"namespace"`
	Names     []string `json:"names"` // 空则表示 --all
}

// WaypointDeleteResponse 删除响应
type WaypointDeleteResponse struct {
	Deleted []string `json:"deleted"`
	Errors  []string `json:"errors,omitempty"`
}

func waypointsFromGateways(gws []gatewayv1.Gateway) []WaypointItem {
	items := make([]WaypointItem, 0, len(gws))
	for _, gw := range gws {
		if gw.Spec.GatewayClassName != waypointGatewayClassName {
			continue
		}
		rev := gw.Labels[labelIstioRev]
		if rev == "" {
			rev = "default"
		}
		trafficFor := gw.Labels[labelWaypointFor]
		programmed := "Unknown"
		for _, c := range gw.Status.Conditions {
			if c.Type == string(gatewayv1.GatewayConditionProgrammed) {
				programmed = string(c.Status)
				break
			}
		}
		items = append(items, WaypointItem{
			Namespace:  gw.Namespace,
			Name:       gw.Name,
			Revision:   rev,
			Programmed: programmed,
			TrafficFor: trafficFor,
			GatewayUID: string(gw.UID),
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Namespace != items[j].Namespace {
			return items[i].Namespace < items[j].Namespace
		}
		return items[i].Name < items[j].Name
	})
	return items
}

// WaypointList 列出 Waypoint（可选 namespace、all-namespaces）
func WaypointList(gwClient gatewayapiclient.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ns := r.URL.Query().Get("namespace")
		allNS := r.URL.Query().Get("allNamespaces") == "true" || r.URL.Query().Get("allNamespaces") == "1"
		if allNS {
			ns = metav1.NamespaceAll
		} else if ns == "" {
			ns = "default"
		}

		var listOpts metav1.ListOptions
		gwList, err := gwClient.GatewayV1().Gateways(ns).List(r.Context(), listOpts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		items := waypointsFromGateways(gwList.Items)
		resp := WaypointListResponse{Items: items}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// WaypointStatus 返回 Waypoint 状态（含 conditions）
func WaypointStatus(gwClient gatewayapiclient.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ns := r.URL.Query().Get("namespace")
		if ns == "" {
			ns = "default"
		}
		gwList, err := gwClient.GatewayV1().Gateways(ns).List(r.Context(), metav1.ListOptions{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		statusItems := make([]WaypointStatusItem, 0)
		for _, gw := range gwList.Items {
			if gw.Spec.GatewayClassName != waypointGatewayClassName {
				continue
			}
			base := WaypointItem{
				Namespace:  gw.Namespace,
				Name:       gw.Name,
				Revision:   gw.Labels[labelIstioRev],
				TrafficFor: gw.Labels[labelWaypointFor],
				GatewayUID: string(gw.UID),
			}
			if base.Revision == "" {
				base.Revision = "default"
			}
			for _, c := range gw.Status.Conditions {
				if c.Type == string(gatewayv1.GatewayConditionProgrammed) {
					base.Programmed = string(c.Status)
					break
				}
			}
			conds := make([]Condition, 0, len(gw.Status.Conditions))
			for _, c := range gw.Status.Conditions {
				conds = append(conds, Condition{
					Type:    string(c.Type),
					Status:  string(c.Status),
					Reason:  c.Reason,
					Message: c.Message,
				})
			}
			statusItems = append(statusItems, WaypointStatusItem{
				WaypointItem: base,
				Conditions:   conds,
			})
		}
		sort.Slice(statusItems, func(i, j int) bool {
			return statusItems[i].Name < statusItems[j].Name
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(WaypointStatusResponse{Items: statusItems})
	}
}

// WaypointApply 创建/应用 Waypoint（支持 enrollNamespace、overwrite、waitReady）
func WaypointApply(gwClient gatewayapiclient.Interface, clientset kubernetes.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req WaypointApplyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Namespace == "" {
			req.Namespace = "default"
		}
		if req.Name == "" {
			req.Name = "waypoint"
		}
		if req.Name == "none" {
			http.Error(w, "invalid waypoint name: 'none' is reserved", http.StatusBadRequest)
			return
		}
		img := req.ProxyImage
		if img == "" {
			img = defaultWaypointImage
		}
		ctx := r.Context()

		// overwrite：若已存在同名 Waypoint，先删除
		if req.Overwrite {
			existing, err := gwClient.GatewayV1().Gateways(req.Namespace).Get(ctx, req.Name, metav1.GetOptions{})
			if err == nil && existing.Spec.GatewayClassName == waypointGatewayClassName {
				_ = gwClient.GatewayV1().Gateways(req.Namespace).Delete(ctx, req.Name, metav1.DeleteOptions{})
				time.Sleep(500 * time.Millisecond) // 等待删除传播
			}
		}

		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      req.Name,
				Namespace: req.Namespace,
				Annotations: map[string]string{
					annotationProxyImage: img,
				},
			},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: waypointGatewayClassName,
				Listeners: []gatewayv1.Listener{{
					Name:     "mesh",
					Port:     gatewayv1.PortNumber(15008),
					Protocol: gatewayv1.ProtocolType("HBONE"),
				}},
			},
		}
		if req.TrafficFor != "" {
			if gw.Labels == nil {
				gw.Labels = make(map[string]string)
			}
			gw.Labels[labelWaypointFor] = req.TrafficFor
		}
		if req.Revision != "" {
			if gw.Labels == nil {
				gw.Labels = make(map[string]string)
			}
			gw.Labels[labelIstioRev] = req.Revision
		}
		_, err := gwClient.GatewayV1().Gateways(req.Namespace).Create(ctx, gw, metav1.CreateOptions{FieldManager: "kmesh-dashboard"})
		if err != nil {
			if errors.IsAlreadyExists(err) && req.Overwrite {
				http.Error(w, "waypoint 已存在且未勾选覆盖，或覆盖删除后未及时创建: "+err.Error(), http.StatusConflict)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// enrollNamespace：为命名空间打 istio.io/use-waypoint 标签
		if req.EnrollNamespace {
			patchBytes, _ := json.Marshal(map[string]interface{}{
				"metadata": map[string]interface{}{
					"labels": map[string]string{labelUseWaypoint: req.Name},
				},
			})
			_, patchErr := clientset.CoreV1().Namespaces().Patch(ctx, req.Namespace, types.MergePatchType, patchBytes, metav1.PatchOptions{})
			if patchErr != nil {
				http.Error(w, "waypoint 已创建，但为命名空间打标签失败: "+patchErr.Error(), http.StatusInternalServerError)
				return
			}
		}

		// waitReady：轮询直到 Gateway Programmed=True
		if req.WaitReady {
			deadline := time.Now().Add(waitReadyTimeout)
			for time.Now().Before(deadline) {
				gwGet, getErr := gwClient.GatewayV1().Gateways(req.Namespace).Get(ctx, req.Name, metav1.GetOptions{})
				if getErr != nil {
					time.Sleep(waitReadyPollInterval)
					continue
				}
				for _, c := range gwGet.Status.Conditions {
					if c.Type == string(gatewayv1.GatewayConditionProgrammed) && c.Status == metav1.ConditionTrue {
						resp := WaypointApplyResponse{
							Namespace: req.Namespace,
							Name:      req.Name,
							Message:   "waypoint " + req.Namespace + "/" + req.Name + " 已应用并就绪",
						}
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusCreated)
						_ = json.NewEncoder(w).Encode(resp)
						return
					}
				}
				time.Sleep(waitReadyPollInterval)
			}
			http.Error(w, "waypoint 已创建，但等待就绪超时（60s）", http.StatusGatewayTimeout)
			return
		}

		resp := WaypointApplyResponse{
			Namespace: req.Namespace,
			Name:      req.Name,
			Message:   "waypoint " + req.Namespace + "/" + req.Name + " applied",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// WaypointDelete 删除 Waypoint
func WaypointDelete(gwClient gatewayapiclient.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req WaypointDeleteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Namespace == "" {
			req.Namespace = "default"
		}
		names := req.Names
		if len(names) == 0 {
			list, err := gwClient.GatewayV1().Gateways(req.Namespace).List(r.Context(), metav1.ListOptions{})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			for _, gw := range list.Items {
				if gw.Spec.GatewayClassName == waypointGatewayClassName {
					names = append(names, gw.Name)
				}
			}
		}
		var deleted []string
		var errs []string
		for _, name := range names {
			if err := gwClient.GatewayV1().Gateways(req.Namespace).Delete(r.Context(), name, metav1.DeleteOptions{}); err != nil {
				errs = append(errs, name+": "+err.Error())
			} else {
				deleted = append(deleted, req.Namespace+"/"+name)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(WaypointDeleteResponse{Deleted: deleted, Errors: errs})
	}
}
