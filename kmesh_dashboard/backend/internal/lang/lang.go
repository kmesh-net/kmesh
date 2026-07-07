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

package lang

import (
	"net/http"
	"strings"
)

// LocaleFromRequest extracts preferred language from Accept-Language header or ?lang= query param
func LocaleFromRequest(r *http.Request) string {
	if q := r.URL.Query().Get("lang"); q != "" {
		if q == "en" || q == "zh" {
			return q
		}
	}
	ah := r.Header.Get("Accept-Language")
	if ah == "" {
		return "zh"
	}
	// Parse first preferred language, e.g. "en-US,en;q=0.9,zh;q=0.8" -> "en"
	parts := strings.SplitN(strings.TrimSpace(ah), ",", 2)
	first := strings.TrimSpace(parts[0])
	// Strip q value if present
	if i := strings.Index(first, ";"); i >= 0 {
		first = strings.TrimSpace(first[:i])
	}
	// "en-US" -> "en", "zh-CN" -> "zh"
	if strings.HasPrefix(first, "en") {
		return "en"
	}
	if strings.HasPrefix(first, "zh") {
		return "zh"
	}
	return "zh"
}

// Msg returns localized message by key; params map is for interpolation (e.g. {"name":"x","namespace":"y"})
func Msg(locale, key string, params map[string]string) string {
	var m map[string]string
	if locale == "en" {
		m = msgsEn
	} else {
		m = msgsZh
	}
	msg := m[key]
	if msg == "" {
		msg = msgsZh[key]
	}
	for k, v := range params {
		msg = strings.ReplaceAll(msg, "{{"+k+"}}", v)
	}
	return msg
}

var msgsZh = map[string]string{
	"accesslog.fetchPodsFailed":      "获取 pods 失败: {{err}}",
	"accesslog.noKmeshPods":          "未找到 kmesh pods。请确认：1) 集群已部署 kmesh；2) Dashboard 后端的 KUBECONFIG 指向正确集群；3) 命名空间为 {{ns}}",
	"accesslog.fetchKmeshPodsFailed": "获取 kmesh pods 失败: {{err}}",
	"accesslog.noKmeshPodsInNs":      "未找到 kmesh pods，请确认集群已部署 kmesh 且命名空间正确",
	"accesslog.podNotFound":          "未找到指定 pod: {{pod}}",
	"accesslog.fetchLogFailed":       "[获取日志失败: {{err}}]",
	"accesslog.noEntriesFound":      "已查询 {{count}} 个 kmesh pod，未发现 accesslog。请确保：1) 先执行 kmeshctl monitoring --all enable；2) 再执行 kmeshctl monitoring --accesslog enable；3) 集群内有 TCP 流量（如 sleep->tcp-echo）",

	"waypoint.fetchPodListFailed":    "获取 Pod 列表失败: {{err}}",
	"waypoint.noPodsYet":             "暂无 Pod（Gateway 已创建，等待控制器部署）",
	"waypoint.applyReady":            "waypoint {{ns}}/{{name}} 已应用并就绪",
	"waypoint.applied":               "waypoint {{ns}}/{{name}} applied",
	"waypoint.labelPatchFailed":      "waypoint 已创建，但为命名空间打标签失败: {{err}}",
	"waypoint.waitReadyTimeout":      "waypoint 已创建，但等待就绪超时（60s）",
	"waypoint.checkFailed":           "检查 Waypoint 状态失败: {{err}}",

	"circuitbreaker.applySuccess":   "熔断策略 {{ns}}/{{name}} 已应用",
	"circuitbreaker.checkFailed":    "检查 Waypoint 状态失败: {{err}}",
	"circuitbreaker.needWaypoint":   "熔断策略作用于 Waypoint，请先在命名空间 {{ns}} 安装 Waypoint",

	"ratelimit.applySuccess": "限流策略 {{ns}}/{{name}} 已下发",
	"ratelimit.checkFailed":  "检查 Waypoint 状态失败: {{err}}",
	"ratelimit.needWaypoint":  "限流策略作用于 Waypoint，请先在命名空间 {{ns}} 安装 Waypoint",

	"authorization.applySuccess": "授权策略 {{ns}}/{{name}} 已应用",

	"customYaml.applySuccess":    "已成功应用到集群",
	"customYaml.unknownModule":    "unknown module: {{module}}",
	"customYaml.emptyYaml":       "YAML 不能为空",
	"customYaml.parseFailed":     "YAML 解析失败: {{err}}",
	"customYaml.missingAPIVersion": "缺少 apiVersion",
	"customYaml.missingKind":     "缺少 kind",
	"customYaml.kindMismatch":    "kind 必须为 {{expected}}，当前为 {{actual}}",
	"customYaml.missingMetadata":  "缺少 metadata",
	"customYaml.missingName":     "metadata.name 不能为空",
}

var msgsEn = map[string]string{
	"accesslog.fetchPodsFailed":      "Failed to get pods: {{err}}",
	"accesslog.noKmeshPods":          "No kmesh pods found. Please confirm: 1) Cluster has kmesh deployed; 2) Dashboard backend KUBECONFIG points to correct cluster; 3) Namespace is {{ns}}",
	"accesslog.fetchKmeshPodsFailed": "Failed to get kmesh pods: {{err}}",
	"accesslog.noKmeshPodsInNs":      "No kmesh pods found. Please confirm kmesh is deployed and namespace is correct",
	"accesslog.podNotFound":          "Pod not found: {{pod}}",
	"accesslog.fetchLogFailed":       "[Failed to get logs: {{err}}]",
	"accesslog.noEntriesFound":      "Queried {{count}} kmesh pod(s), no accesslog found. Ensure: 1) Run kmeshctl monitoring --all enable; 2) Run kmeshctl monitoring --accesslog enable; 3) TCP traffic exists (e.g. sleep->tcp-echo)",

	"waypoint.fetchPodListFailed":    "Failed to get Pod list: {{err}}",
	"waypoint.noPodsYet":             "No pods yet (Gateway created, waiting for controller)",
	"waypoint.applyReady":            "Waypoint {{ns}}/{{name}} applied and ready",
	"waypoint.applied":               "Waypoint {{ns}}/{{name}} applied",
	"waypoint.labelPatchFailed":      "Waypoint created, but failed to label namespace: {{err}}",
	"waypoint.waitReadyTimeout":      "Waypoint created, but wait ready timeout (60s)",
	"waypoint.checkFailed":           "Failed to check Waypoint status: {{err}}",

	"circuitbreaker.applySuccess":   "Circuit breaker policy {{ns}}/{{name}} applied",
	"circuitbreaker.checkFailed":    "Failed to check Waypoint status: {{err}}",
	"circuitbreaker.needWaypoint":   "Circuit breaker targets Waypoint. Please install Waypoint in namespace {{ns}} first",

	"ratelimit.applySuccess": "Rate limit policy {{ns}}/{{name}} applied",
	"ratelimit.checkFailed":  "Failed to check Waypoint status: {{err}}",
	"ratelimit.needWaypoint":  "Rate limit targets Waypoint. Please install Waypoint in namespace {{ns}} first",

	"authorization.applySuccess": "Authorization policy {{ns}}/{{name}} applied",

	"customYaml.applySuccess":    "Successfully applied to cluster",
	"customYaml.unknownModule":   "Unknown module: {{module}}",
	"customYaml.emptyYaml":       "YAML cannot be empty",
	"customYaml.parseFailed":     "YAML parse failed: {{err}}",
	"customYaml.missingAPIVersion": "Missing apiVersion",
	"customYaml.missingKind":     "Missing kind",
	"customYaml.kindMismatch":    "Kind must be {{expected}}, got {{actual}}",
	"customYaml.missingMetadata":  "Missing metadata",
	"customYaml.missingName":     "metadata.name cannot be empty",
}
