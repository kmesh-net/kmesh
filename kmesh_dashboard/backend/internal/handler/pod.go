/*
 * Copyright The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package handler

import (
	"bufio"
	"encoding/json"
	"net/http"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
)

const (
	defaultPodLogTail = int64(200)
	maxPodLogTail     = int64(5000)
)

// PodDetailResponse Pod 详情（describe 风格：完整状态、Events）
type PodDetailResponse struct {
	Namespace   string            `json:"namespace"`
	Name        string            `json:"name"`
	Phase       string            `json:"phase"`
	Reason      string            `json:"reason,omitempty"`
	Message     string            `json:"message,omitempty"`
	Node        string            `json:"node,omitempty"`
	PodIP       string            `json:"podIP,omitempty"`
	StartTime   string            `json:"startTime,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Containers  []ContainerStatus `json:"containers,omitempty"`
	Conditions  []PodCondition   `json:"conditions,omitempty"`
	Events      []PodEvent       `json:"events,omitempty"`
	Error       string           `json:"error,omitempty"`
}

// ContainerStatus 容器状态
type ContainerStatus struct {
	Name          string `json:"name"`
	Image         string `json:"image,omitempty"`
	Ready         bool   `json:"ready"`
	Restarts      int32  `json:"restartCount"`
	State         string `json:"state"` // Running, Waiting, Terminated
	Reason        string `json:"reason,omitempty"`
	Message       string `json:"message,omitempty"`
	LastState     string `json:"lastState,omitempty"`     // 上次终止状态描述
	LastExitCode  int32  `json:"lastExitCode,omitempty"` // 上次终止退出码
	LastFinishedAt string `json:"lastFinishedAt,omitempty"`
	ExitCode      int32  `json:"exitCode,omitempty"`      // 当前 Terminated 退出码
	StartedAt    string `json:"startedAt,omitempty"`
	FinishedAt   string `json:"finishedAt,omitempty"`
}

// PodCondition Pod 条件
type PodCondition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason,omitempty"`
	Message            string `json:"message,omitempty"`
	LastTransitionTime string `json:"lastTransitionTime,omitempty"`
}

// PodEvent 事件（类似 kubectl describe 中的 Events）
type PodEvent struct {
	FirstSeen string `json:"firstSeen"`
	LastSeen  string `json:"lastSeen"`
	Type      string `json:"type"`
	Reason    string `json:"reason"`
	Message   string `json:"message"`
	Count     int32  `json:"count,omitempty"`
	Source    string `json:"source,omitempty"` // component/kind
}

// PodLogsResponse Pod 日志
type PodLogsResponse struct {
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	Container string   `json:"container,omitempty"`
	Lines     []string `json:"lines"`
	Error     string   `json:"error,omitempty"`
}

// PodDetail 获取 Pod 详情（含 Events，类似 kubectl describe）
func PodDetail(clientset kubernetes.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ns := r.URL.Query().Get("namespace")
		name := r.URL.Query().Get("name")
		if ns == "" || name == "" {
			http.Error(w, "namespace and name are required", http.StatusBadRequest)
			return
		}

		pod, err := clientset.CoreV1().Pods(ns).Get(r.Context(), name, metav1.GetOptions{})
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PodDetailResponse{
				Namespace: ns,
				Name:      name,
				Error:     err.Error(),
			})
			return
		}

		resp := buildPodDetailResponse(pod)

		// 获取与该 Pod 相关的 Events
		eventList, err := clientset.CoreV1().Events(ns).List(r.Context(), metav1.ListOptions{
			FieldSelector: fields.OneTermEqualSelector("involvedObject.name", name).String(),
		})
		if err == nil && len(eventList.Items) > 0 {
			events := make([]PodEvent, 0, len(eventList.Items))
			for _, e := range eventList.Items {
				pe := PodEvent{
					LastSeen: e.LastTimestamp.Format("2006-01-02 15:04:05"),
					Type:     e.Type,
					Reason:   e.Reason,
					Message:  e.Message,
					Count:    e.Count,
				}
				if !e.FirstTimestamp.IsZero() {
					pe.FirstSeen = e.FirstTimestamp.Format("2006-01-02 15:04:05")
				}
				if e.Source.Component != "" || e.Source.Host != "" {
					pe.Source = e.Source.Component
					if e.Source.Host != "" {
						if pe.Source != "" {
							pe.Source += "/"
						}
						pe.Source += e.Source.Host
					}
				}
				events = append(events, pe)
			}
			resp.Events = events
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func buildPodDetailResponse(pod *corev1.Pod) PodDetailResponse {
	resp := PodDetailResponse{
		Namespace: pod.Namespace,
		Name:      pod.Name,
		Phase:     string(pod.Status.Phase),
		Reason:    pod.Status.Reason,
		Message:   pod.Status.Message,
		Node:      pod.Spec.NodeName,
		PodIP:     pod.Status.PodIP,
	}
	if pod.Status.StartTime != nil {
		resp.StartTime = pod.Status.StartTime.Format("2006-01-02 15:04:05")
	}
	if len(pod.Labels) > 0 {
		resp.Labels = pod.Labels
	}
	if len(pod.Annotations) > 0 {
		resp.Annotations = pod.Annotations
	}

	for i, c := range pod.Status.ContainerStatuses {
		cs := ContainerStatus{
			Name:     c.Name,
			Ready:    c.Ready,
			Restarts: c.RestartCount,
		}
		if i < len(pod.Spec.Containers) {
			cs.Image = pod.Spec.Containers[i].Image
		}
		if c.State.Running != nil {
			cs.State = "Running"
			if !c.State.Running.StartedAt.IsZero() {
				cs.StartedAt = c.State.Running.StartedAt.Format("2006-01-02 15:04:05")
			}
		} else if c.State.Waiting != nil {
			cs.State = "Waiting"
			cs.Reason = c.State.Waiting.Reason
			cs.Message = c.State.Waiting.Message
		} else if c.State.Terminated != nil {
			cs.State = "Terminated"
			cs.Reason = c.State.Terminated.Reason
			cs.Message = c.State.Terminated.Message
			cs.ExitCode = c.State.Terminated.ExitCode
			if !c.State.Terminated.FinishedAt.IsZero() {
				cs.FinishedAt = c.State.Terminated.FinishedAt.Format("2006-01-02 15:04:05")
			}
		}
		if c.LastTerminationState.Terminated != nil {
			cs.LastState = "Terminated"
			if c.LastTerminationState.Terminated.Reason != "" {
				cs.LastState += " (" + c.LastTerminationState.Terminated.Reason + ")"
			}
			cs.LastExitCode = c.LastTerminationState.Terminated.ExitCode
			if !c.LastTerminationState.Terminated.FinishedAt.IsZero() {
				cs.LastFinishedAt = c.LastTerminationState.Terminated.FinishedAt.Format("2006-01-02 15:04:05")
			}
		}
		resp.Containers = append(resp.Containers, cs)
	}

	for _, c := range pod.Status.Conditions {
		pc := PodCondition{
			Type:    string(c.Type),
			Status:  string(c.Status),
			Reason:  c.Reason,
			Message: c.Message,
		}
		if !c.LastTransitionTime.IsZero() {
			pc.LastTransitionTime = c.LastTransitionTime.Format("2006-01-02 15:04:05")
		}
		resp.Conditions = append(resp.Conditions, pc)
	}

	return resp
}

// PodLogs 获取 Pod 日志（通用，可指定 container）
func PodLogs(clientset kubernetes.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ns := r.URL.Query().Get("namespace")
		name := r.URL.Query().Get("name")
		container := r.URL.Query().Get("container")
		if ns == "" || name == "" {
			http.Error(w, "namespace and name are required", http.StatusBadRequest)
			return
		}

		tailLines := defaultPodLogTail
		if s := r.URL.Query().Get("tail"); s != "" {
			if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 && n <= maxPodLogTail {
				tailLines = n
			}
		}

		opts := &corev1.PodLogOptions{
			TailLines: &tailLines,
		}
		if container != "" {
			opts.Container = container
		}

		req := clientset.CoreV1().Pods(ns).GetLogs(name, opts)
		stream, err := req.Stream(r.Context())
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PodLogsResponse{
				Namespace: ns,
				Name:      name,
				Container: container,
				Error:     err.Error(),
			})
			return
		}
		defer stream.Close()

		var lines []string
		scanner := bufio.NewScanner(stream)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(PodLogsResponse{
				Namespace: ns,
				Name:      name,
				Container: container,
				Error:     err.Error(),
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(PodLogsResponse{
			Namespace: ns,
			Name:      name,
			Container: container,
			Lines:     lines,
		})
	}
}
