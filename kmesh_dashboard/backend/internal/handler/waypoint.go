package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapiclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	corev1 "k8s.io/api/core/v1"
	"kmesh.net/kmesh-dashboard/backend/internal/lang"
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
	labelGatewayName         = "gateway.networking.k8s.io/gateway-name"
	annotationProxyImage     = "sidecar.istio.io/proxyImage"
	defaultWaypointImage     = "ghcr.io/kmesh-net/waypoint:latest"
	waitReadyTimeout         = 60 * time.Second
	waitReadyPollInterval    = 2 * time.Second
)

// HasWaypointInNamespace checks whether Waypoint is installed in the namespace.
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

// WaypointListResponse is the list response payload.
type WaypointListResponse struct {
	Items []WaypointItem `json:"items"`
}

// WaypointItem represents one Waypoint entry.
type WaypointItem struct {
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	Revision   string `json:"revision"`
	Programmed string `json:"programmed"`
	TrafficFor string `json:"trafficFor,omitempty"`
	GatewayUID string `json:"gatewayUID,omitempty"`
}

// WaypointStatusResponse is the status response payload (including conditions).
type WaypointStatusResponse struct {
	Items []WaypointStatusItem `json:"items"`
}

// WaypointStatusItem represents one status entry (Gateway conditions and Waypoint Pod status).
type WaypointStatusItem struct {
	WaypointItem
	Conditions []Condition `json:"conditions,omitempty"`
	PodStatus  *PodStatus  `json:"podStatus,omitempty"`
}

// PodStatus is the summary of Waypoint Pod status.
type PodStatus struct {
	Ready   int               `json:"ready"`          // Number of ready Pods.
	Total   int               `json:"total"`          // Total number of Pods.
	Phase   string            `json:"phase"`          // Main phase: Running/Pending/Failed.
	Message string            `json:"message"`        // Short summary, e.g. "1/1 Running".
	Pods    []WaypointPodInfo `json:"pods,omitempty"` // Per-Pod details (optional).
}

// WaypointPodInfo describes status for one Waypoint Pod.
type WaypointPodInfo struct {
	Name   string `json:"name"`
	Phase  string `json:"phase"`
	Ready  bool   `json:"ready"`
	Reason string `json:"reason,omitempty"`
}

// Condition matches metav1.Condition.
type Condition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// WaypointApplyRequest is the install request payload.
type WaypointApplyRequest struct {
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	TrafficFor      string `json:"trafficFor"` // service | workload | all | empty means default
	EnrollNamespace bool   `json:"enrollNamespace"`
	Overwrite       bool   `json:"overwrite"`
	WaitReady       bool   `json:"waitReady"`
	Revision        string `json:"revision"`
	ProxyImage      string `json:"proxyImage"`
}

// WaypointApplyResponse is the install response payload.
type WaypointApplyResponse struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Message   string `json:"message"`
}

// WaypointDeleteRequest is the delete request payload (by names or all).
type WaypointDeleteRequest struct {
	Namespace string   `json:"namespace"`
	Names     []string `json:"names"` // Empty means --all.
}

// WaypointDeleteResponse is the delete response payload.
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

// WaypointList lists Waypoints (supports optional namespace and all-namespaces).
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

// WaypointStatus returns Waypoint status (Gateway conditions and Waypoint Pod status).
func WaypointStatus(gwClient gatewayapiclient.Interface, clientset kubernetes.Interface) http.HandlerFunc {
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
			item := WaypointStatusItem{
				WaypointItem: base,
				Conditions:   conds,
			}
			// Query Waypoint Pod status for this Gateway via gateway.networking.k8s.io/gateway-name label.
			if clientset != nil {
				loc := lang.LocaleFromRequest(r)
				podStatus := getWaypointPodStatus(r.Context(), clientset, gw.Namespace, gw.Name, loc)
				item.PodStatus = podStatus
			}
			statusItems = append(statusItems, item)
		}
		sort.Slice(statusItems, func(i, j int) bool {
			return statusItems[i].Name < statusItems[j].Name
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(WaypointStatusResponse{Items: statusItems})
	}
}

// getWaypointPodStatus gets Waypoint Pod status filtered by gateway.networking.k8s.io/gateway-name label.
func getWaypointPodStatus(ctx context.Context, clientset kubernetes.Interface, namespace, gatewayName, locale string) *PodStatus {
	selector := labelGatewayName + "=" + gatewayName
	podList, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return &PodStatus{Total: 0, Phase: "Unknown", Message: lang.Msg(locale, "waypoint.fetchPodListFailed", map[string]string{"err": err.Error()})}
	}
	if len(podList.Items) == 0 {
		return &PodStatus{Total: 0, Phase: "Pending", Message: lang.Msg(locale, "waypoint.noPodsYet", nil)}
	}
	ready := 0
	phaseCount := map[string]int{}
	pods := make([]WaypointPodInfo, 0, len(podList.Items))
	for _, p := range podList.Items {
		pPhase := string(p.Status.Phase)
		phaseCount[pPhase]++
		pReady := false
		for _, c := range p.Status.Conditions {
			if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
				pReady = true
				ready++
				break
			}
		}
		reason := ""
		if p.Status.Reason != "" {
			reason = p.Status.Reason
		} else if len(p.Status.ContainerStatuses) > 0 {
			for _, cs := range p.Status.ContainerStatuses {
				if cs.State.Waiting != nil {
					reason = cs.State.Waiting.Reason
					break
				}
			}
		}
		pods = append(pods, WaypointPodInfo{
			Name:   p.Name,
			Phase:  pPhase,
			Ready:  pReady,
			Reason: reason,
		})
	}
	// Main phase priority: Running > Pending > Failed.
	mainPhase := "Running"
	if phaseCount["Failed"] > 0 {
		mainPhase = "Failed"
	} else if phaseCount["Pending"] > 0 {
		mainPhase = "Pending"
	} else if phaseCount["Running"] == 0 {
		mainPhase = "Unknown"
	}
	msg := fmt.Sprintf("%d/%d %s", ready, len(podList.Items), mainPhase)
	return &PodStatus{
		Ready:   ready,
		Total:   len(podList.Items),
		Phase:   mainPhase,
		Message: msg,
		Pods:    pods,
	}
}

// WaypointApply creates/applies Waypoint (supports enrollNamespace, overwrite, waitReady).
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

		// overwrite: if a Waypoint with the same name exists, delete it first.
		if req.Overwrite {
			existing, err := gwClient.GatewayV1().Gateways(req.Namespace).Get(ctx, req.Name, metav1.GetOptions{})
			if err == nil && existing.Spec.GatewayClassName == waypointGatewayClassName {
				_ = gwClient.GatewayV1().Gateways(req.Namespace).Delete(ctx, req.Name, metav1.DeleteOptions{})
				time.Sleep(500 * time.Millisecond) // Wait for deletion propagation.
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

		// enrollNamespace: add istio.io/use-waypoint label to the namespace.
		if req.EnrollNamespace {
			patchBytes, _ := json.Marshal(map[string]interface{}{
				"metadata": map[string]interface{}{
					"labels": map[string]string{labelUseWaypoint: req.Name},
				},
			})
			_, patchErr := clientset.CoreV1().Namespaces().Patch(ctx, req.Namespace, types.MergePatchType, patchBytes, metav1.PatchOptions{})
			if patchErr != nil {
				loc := lang.LocaleFromRequest(r)
				http.Error(w, lang.Msg(loc, "waypoint.labelPatchFailed", map[string]string{"err": patchErr.Error()}), http.StatusInternalServerError)
				return
			}
		}

		// waitReady: poll until Gateway Programmed=True.
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
						loc := lang.LocaleFromRequest(r)
						resp := WaypointApplyResponse{
							Namespace: req.Namespace,
							Name:      req.Name,
							Message:   lang.Msg(loc, "waypoint.applyReady", map[string]string{"ns": req.Namespace, "name": req.Name}),
						}
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusCreated)
						_ = json.NewEncoder(w).Encode(resp)
						return
					}
				}
				time.Sleep(waitReadyPollInterval)
			}
			loc := lang.LocaleFromRequest(r)
			http.Error(w, lang.Msg(loc, "waypoint.waitReadyTimeout", nil), http.StatusGatewayTimeout)
			return
		}

		loc := lang.LocaleFromRequest(r)
		resp := WaypointApplyResponse{
			Namespace: req.Namespace,
			Name:      req.Name,
			Message:   lang.Msg(loc, "waypoint.applied", map[string]string{"ns": req.Namespace, "name": req.Name}),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// WaypointDelete deletes Waypoint resources.
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
