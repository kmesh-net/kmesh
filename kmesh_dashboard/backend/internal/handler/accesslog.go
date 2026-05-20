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
	"kmesh.net/kmesh-dashboard/backend/internal/lang"
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

// AccesslogEntry represents one accesslog item with pod and raw content.
type AccesslogEntry struct {
	Pod     string `json:"pod"`
	Node    string `json:"node,omitempty"`
	Content string `json:"content"`
}

// AccesslogResponse is the response payload for accesslog listing.
type AccesslogResponse struct {
	Entries     []AccesslogEntry `json:"entries"`
	PodsQueried []string         `json:"podsQueried,omitempty"` // Actual queried pod list for troubleshooting.
	Message     string           `json:"message,omitempty"`
}

// KmeshPodsResponse is the kmesh pod list used for connectivity troubleshooting.
type KmeshPodsResponse struct {
	Pods    []PodInfo `json:"pods"`
	Message string    `json:"message,omitempty"`
}

// PodInfo is a compact pod info view.
type PodInfo struct {
	Name   string `json:"name"`
	Node   string `json:"node"`
	Status string `json:"status"`
}

// KmeshPodsList lists kmesh pods to verify Dashboard cluster visibility.
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
			loc := lang.LocaleFromRequest(r)
			_ = json.NewEncoder(w).Encode(KmeshPodsResponse{Message: lang.Msg(loc, "accesslog.fetchPodsFailed", map[string]string{"err": err.Error()})})
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
		loc := lang.LocaleFromRequest(r)
		resp := KmeshPodsResponse{Pods: pods}
		if len(pods) == 0 {
			resp.Message = lang.Msg(loc, "accesslog.noKmeshPods", map[string]string{"ns": ns})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// AccesslogList fetches accesslog entries from kmesh pods via K8s Pod Logs API.
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
			loc := lang.LocaleFromRequest(r)
			_ = json.NewEncoder(w).Encode(AccesslogResponse{Message: lang.Msg(loc, "accesslog.fetchKmeshPodsFailed", map[string]string{"err": err.Error()})})
			return
		}
		if len(podList.Items) == 0 {
			w.Header().Set("Content-Type", "application/json")
			loc := lang.LocaleFromRequest(r)
			_ = json.NewEncoder(w).Encode(AccesslogResponse{
				Entries: []AccesslogEntry{},
				Message: lang.Msg(loc, "accesslog.noKmeshPodsInNs", nil),
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
				loc := lang.LocaleFromRequest(r)
				_ = json.NewEncoder(w).Encode(AccesslogResponse{
					Entries: []AccesslogEntry{},
					Message: lang.Msg(loc, "accesslog.podNotFound", map[string]string{"pod": podName}),
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
				loc := lang.LocaleFromRequest(r)
				entries = append(entries, AccesslogEntry{
					Pod:     pod.Name,
					Node:    pod.Spec.NodeName,
					Content: lang.Msg(loc, "accesslog.fetchLogFailed", map[string]string{"err": err.Error()}),
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

		loc := lang.LocaleFromRequest(r)
		resp := AccesslogResponse{Entries: entries, PodsQueried: podsQueried}
		if len(entries) == 0 && len(podsQueried) > 0 {
			resp.Message = lang.Msg(loc, "accesslog.noEntriesFound", map[string]string{"count": strconv.Itoa(len(podsQueried))})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}
