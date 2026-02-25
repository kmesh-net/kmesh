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
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	kmeshNamespace   = "kmesh-system"
	kmeshLabel       = "app=kmesh"
	kmeshContainer   = "kmesh"
	accesslogPrefix  = "accesslog:"
	defaultTailLines = int64(200)
)

// AccesslogEntry 单条 accesslog，含 pod 与原始内容
type AccesslogEntry struct {
	Pod     string `json:"pod"`
	Node    string `json:"node,omitempty"`
	Content string `json:"content"`
}

// AccesslogResponse accesslog 列表响应
type AccesslogResponse struct {
	Entries     []AccesslogEntry `json:"entries"`
	PodsQueried []string         `json:"podsQueried,omitempty"` // 实际查询的 pod 列表，用于排查
	Message     string           `json:"message,omitempty"`
}

// KmeshPodsResponse kmesh pods 列表，用于排查连接问题
type KmeshPodsResponse struct {
	Pods    []PodInfo `json:"pods"`
	Message string    `json:"message,omitempty"`
}

// PodInfo 简要 pod 信息
type PodInfo struct {
	Name   string `json:"name"`
	Node   string `json:"node"`
	Status string `json:"status"`
}

// KmeshPodsList 列出 kmesh pods（用于排查 Dashboard 是否能看到集群）
func KmeshPodsList(clientset kubernetes.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ns := r.URL.Query().Get("namespace")
		if ns == "" {
			ns = kmeshNamespace
		}
		podList, err := clientset.CoreV1().Pods(ns).List(r.Context(), metav1.ListOptions{LabelSelector: kmeshLabel})
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(KmeshPodsResponse{Message: "获取 pods 失败: " + err.Error()})
			return
		}
		pods := make([]PodInfo, 0, len(podList.Items))
		for _, p := range podList.Items {
			status := string(p.Status.Phase)
			for _, c := range p.Status.ContainerStatuses {
				if !c.Ready {
					status = "NotReady"
					break
				}
			}
			pods = append(pods, PodInfo{Name: p.Name, Node: p.Spec.NodeName, Status: status})
		}
		resp := KmeshPodsResponse{Pods: pods}
		if len(pods) == 0 {
			resp.Message = "未找到 kmesh pods。请确认：1) 集群已部署 kmesh；2) Dashboard 后端的 KUBECONFIG 指向正确集群；3) 命名空间为 " + ns
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// AccesslogList 从 kmesh pods 获取 accesslog（通过 K8s Pod Logs API）
func AccesslogList(clientset kubernetes.Interface) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		tailLines := defaultTailLines
		if s := r.URL.Query().Get("tail"); s != "" {
			if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 && n <= 2000 {
				tailLines = n
			}
		}
		podName := r.URL.Query().Get("pod")
		ns := r.URL.Query().Get("namespace")
		if ns == "" {
			ns = kmeshNamespace
		}

		podList, err := clientset.CoreV1().Pods(ns).List(r.Context(), metav1.ListOptions{
			LabelSelector: kmeshLabel,
		})
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(AccesslogResponse{Message: "获取 kmesh pods 失败: " + err.Error()})
			return
		}
		if len(podList.Items) == 0 {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(AccesslogResponse{
				Entries: []AccesslogEntry{},
				Message: "未找到 kmesh pods，请确认集群已部署 kmesh 且命名空间正确",
			})
			return
		}

		var entries []AccesslogEntry
		var podsQueried []string
		podsToQuery := podList.Items
		if podName != "" {
			var found *corev1.Pod
			for i := range podsToQuery {
				if podsToQuery[i].Name == podName {
					found = &podsToQuery[i]
					break
				}
			}
			if found == nil {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(AccesslogResponse{
					Entries: []AccesslogEntry{},
					Message: "未找到指定 pod: " + podName,
				})
				return
			}
			podsToQuery = []corev1.Pod{*found}
		}

		for _, pod := range podsToQuery {
			podsQueried = append(podsQueried, pod.Name)
			req := clientset.CoreV1().Pods(ns).GetLogs(pod.Name, &corev1.PodLogOptions{
				Container: kmeshContainer,
				TailLines: &tailLines,
			})
			stream, err := req.Stream(r.Context())
			if err != nil {
				entries = append(entries, AccesslogEntry{
					Pod:     pod.Name,
					Node:    pod.Spec.NodeName,
					Content: "[获取日志失败: " + err.Error() + "]",
				})
				continue
			}
			scanner := bufio.NewScanner(stream)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, accesslogPrefix) {
					content := line
					if idx := strings.Index(line, accesslogPrefix); idx >= 0 {
						content = strings.TrimSpace(line[idx+len(accesslogPrefix):])
					}
					entries = append(entries, AccesslogEntry{
						Pod:     pod.Name,
						Node:    pod.Spec.NodeName,
						Content: content,
					})
				}
			}
			_ = stream.Close()
		}

		resp := AccesslogResponse{Entries: entries, PodsQueried: podsQueried}
		if len(entries) == 0 && len(podsQueried) > 0 {
			resp.Message = "已查询 " + strconv.Itoa(len(podsQueried)) + " 个 kmesh pod，未发现 accesslog。请确保：1) 先执行 kmeshctl monitoring --all enable；2) 再执行 kmeshctl monitoring --accesslog enable；3) 集群内有 TCP 流量（如 sleep->tcp-echo）"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}
