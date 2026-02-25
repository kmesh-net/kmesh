package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

// MetricsOverviewResponse 指标大盘统一响应（Kmesh L4 累计值）
type MetricsOverviewResponse struct {
	Available bool   `json:"available"`
	Message  string `json:"message,omitempty"`
	// Kmesh L4 工作负载指标（累计值）
	WorkloadConnOpened  float64 `json:"workloadConnOpened"`
	WorkloadConnClosed  float64 `json:"workloadConnClosed"`
	WorkloadRecvBytes   float64 `json:"workloadRecvBytes"`
	WorkloadSentBytes   float64 `json:"workloadSentBytes"`
	WorkloadConnFailed  float64 `json:"workloadConnFailed"`
	// Kmesh L4 服务指标（累计值）
	ServiceConnOpened  float64 `json:"serviceConnOpened"`
	ServiceConnClosed  float64 `json:"serviceConnClosed"`
	ServiceRecvBytes   float64 `json:"serviceRecvBytes"`
	ServiceSentBytes   float64 `json:"serviceSentBytes"`
	ServiceConnFailed  float64 `json:"serviceConnFailed"`
}

func getPrometheusURL() string {
	return os.Getenv("PROMETHEUS_URL")
}

func toFloat64(v interface{}) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return f, err == nil
	default:
		return 0, false
	}
}

// queryPrometheusInstant 执行瞬时查询，返回所有匹配序列的 value 之和
func queryPrometheusInstant(baseURL, query string) (float64, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return 0, err
	}
	u.Path = "/api/v1/query"
	u.RawQuery = url.Values{"query": {query}}.Encode()
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	var pr struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Value []interface{} `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return 0, err
	}
	if pr.Status != "success" {
		return 0, nil
	}
	var sum float64
	for _, r := range pr.Data.Result {
		if len(r.Value) >= 2 {
			if v, ok := toFloat64(r.Value[1]); ok {
				sum += v
			}
		}
	}
	return sum, nil
}

// MetricsDatasource 返回 Prometheus 是否可用
func MetricsDatasource() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		base := getPrometheusURL()
		res := struct {
			Available bool   `json:"available"`
			URL       string `json:"url,omitempty"`
			Message   string `json:"message,omitempty"`
		}{}
		if base == "" {
			res.Available = false
			res.Message = "未配置 PROMETHEUS_URL 环境变量"
		} else {
			res.Available = true
			res.URL = base
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	}
}

// MetricsOverview 查询 Kmesh L4 累计指标并返回（直接获取数值）
func MetricsOverview() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		base := getPrometheusURL()
		resp := MetricsOverviewResponse{}
		if base == "" {
			resp.Available = false
			resp.Message = "未配置 PROMETHEUS_URL，无法查询 Prometheus"
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		namespace := r.URL.Query().Get("namespace")

		// 工作负载指标 label：destination_workload_namespace
		wlFilter := ""
		if namespace != "" {
			wlFilter = fmt.Sprintf(`{destination_workload_namespace="%s"}`, namespace)
		}
		// 服务指标 label：destination_service_namespace
		svcFilter := ""
		if namespace != "" {
			svcFilter = fmt.Sprintf(`{destination_service_namespace="%s"}`, namespace)
		}

		// Kmesh L4 工作负载指标（累计值，直接 sum）
		resp.WorkloadConnOpened, _ = queryPrometheusInstant(base, fmt.Sprintf("sum(kmesh_tcp_workload_connections_opened_total%s)", wlFilter))
		resp.WorkloadConnClosed, _ = queryPrometheusInstant(base, fmt.Sprintf("sum(kmesh_tcp_workload_connections_closed_total%s)", wlFilter))
		resp.WorkloadRecvBytes, _ = queryPrometheusInstant(base, fmt.Sprintf("sum(kmesh_tcp_workload_received_bytes_total%s)", wlFilter))
		resp.WorkloadSentBytes, _ = queryPrometheusInstant(base, fmt.Sprintf("sum(kmesh_tcp_workload_sent_bytes_total%s)", wlFilter))
		resp.WorkloadConnFailed, _ = queryPrometheusInstant(base, fmt.Sprintf("sum(kmesh_tcp_workload_conntections_failed_total%s)", wlFilter))

		// Kmesh L4 服务指标（累计值，直接 sum，注意 conntections 拼写）
		resp.ServiceConnOpened, _ = queryPrometheusInstant(base, fmt.Sprintf("sum(kmesh_tcp_connections_opened_total%s)", svcFilter))
		resp.ServiceConnClosed, _ = queryPrometheusInstant(base, fmt.Sprintf("sum(kmesh_tcp_connections_closed_total%s)", svcFilter))
		resp.ServiceRecvBytes, _ = queryPrometheusInstant(base, fmt.Sprintf("sum(kmesh_tcp_received_bytes_total%s)", svcFilter))
		resp.ServiceSentBytes, _ = queryPrometheusInstant(base, fmt.Sprintf("sum(kmesh_tcp_sent_bytes_total%s)", svcFilter))
		resp.ServiceConnFailed, _ = queryPrometheusInstant(base, fmt.Sprintf("sum(kmesh_tcp_conntections_failed_total%s)", svcFilter))

		resp.Available = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}
