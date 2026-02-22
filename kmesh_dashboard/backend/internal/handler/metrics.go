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

// Prometheus 返回的 query_range 结构（仅取所需字段）
type promQueryRangeResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Values [][]interface{}   `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

// MetricsOverviewResponse 指标大盘统一响应（Kmesh L4 + Istio L7，覆盖 throughput / error rates / latency）
type MetricsOverviewResponse struct {
	Available       bool           `json:"available"`
	Message        string         `json:"message,omitempty"`
	// Kmesh L4 TCP 指标
	ConnOpenedRate []MetricsPoint `json:"connOpenedRate"`   // 连接建立速率
	ConnClosedRate []MetricsPoint `json:"connClosedRate"`   // 连接关闭速率
	BytesSentRate  []MetricsPoint `json:"bytesSentRate"`    // 发送字节率
	BytesRecvRate  []MetricsPoint `json:"bytesRecvRate"`    // 接收字节率
	ConnFailedRate []MetricsPoint `json:"connFailedRate"`   // 连接失败速率（L4 错误率）
	// Istio L7 指标（可选，集群未暴露时为空）
	Rps        []MetricsPoint `json:"rps"`        // 请求量 RPS istio_requests_total
	ErrorRate  []MetricsPoint `json:"errorRate"`  // 5xx 错误率 0~1
	LatencyP50 []MetricsPoint `json:"latencyP50"` // 延迟 P50 ms
	LatencyP95 []MetricsPoint `json:"latencyP95"` // 延迟 P95 ms
	LatencyP99 []MetricsPoint `json:"latencyP99"` // 延迟 P99 ms
}

// MetricsPoint 时序点
type MetricsPoint struct {
	Time  int64   `json:"time"`
	Value float64 `json:"value"`
}

func getPrometheusURL() string {
	return os.Getenv("PROMETHEUS_URL")
}

// queryPrometheusRange 调用 Prometheus query_range API
func queryPrometheusRange(baseURL, query string, start, end int64, step int64) ([]MetricsPoint, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	u.Path = "/api/v1/query_range"
	u.RawQuery = url.Values{
		"query": {query},
		"start": {strconv.FormatInt(start, 10)},
		"end":   {strconv.FormatInt(end, 10)},
		"step":  {strconv.FormatInt(step, 10) + "s"},
	}.Encode()
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var pr promQueryRangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return nil, err
	}
	if pr.Status != "success" || len(pr.Data.Result) == 0 {
		return nil, nil
	}
	var points []MetricsPoint
	for _, r := range pr.Data.Result {
		for _, v := range r.Values {
			if len(v) < 2 {
				continue
			}
			ts, _ := toFloat64(v[0])
			val, _ := toFloat64(v[1])
			points = append(points, MetricsPoint{Time: int64(ts), Value: val})
		}
		break
	}
	return points, nil
}

func toFloat64(v interface{}) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	default:
		return 0, false
	}
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

// MetricsOverview 查询 Kmesh L4 TCP 指标并返回（服务维度）
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
		startStr := r.URL.Query().Get("start")
		endStr := r.URL.Query().Get("end")
		stepStr := r.URL.Query().Get("step")
		end := time.Now().Unix()
		start := end - 3600
		step := int64(60)
		if startStr != "" {
			if s, err := strconv.ParseInt(startStr, 10, 64); err == nil {
				start = s
			}
		}
		if endStr != "" {
			if e, err := strconv.ParseInt(endStr, 10, 64); err == nil {
				end = e
			}
		}
		if stepStr != "" {
			if st, err := strconv.ParseInt(stepStr, 10, 64); err == nil && st > 0 {
				step = st
			}
		}
		labelFilter := ""
		if namespace != "" {
			labelFilter = fmt.Sprintf(`{destination_service_namespace="%s"}`, namespace)
		}
		// Kmesh L4 服务指标（与 pkg/controller/telemetry 一致）
		qOpened := fmt.Sprintf(`sum(rate(kmesh_tcp_connections_opened_total%s[1m]))`, labelFilter)
		qClosed := fmt.Sprintf(`sum(rate(kmesh_tcp_connections_closed_total%s[1m]))`, labelFilter)
		qSent := fmt.Sprintf(`sum(rate(kmesh_tcp_sent_bytes_total%s[1m]))`, labelFilter)
		qRecv := fmt.Sprintf(`sum(rate(kmesh_tcp_received_bytes_total%s[1m]))`, labelFilter)
		qFailed := fmt.Sprintf(`sum(rate(kmesh_tcp_conntections_failed_total%s[1m]))`, labelFilter)
		resp.ConnOpenedRate, _ = queryPrometheusRange(base, qOpened, start, end, step)
		resp.ConnClosedRate, _ = queryPrometheusRange(base, qClosed, start, end, step)
		resp.BytesSentRate, _ = queryPrometheusRange(base, qSent, start, end, step)
		resp.BytesRecvRate, _ = queryPrometheusRange(base, qRecv, start, end, step)
		resp.ConnFailedRate, _ = queryPrometheusRange(base, qFailed, start, end, step)

		// Istio L7 指标（throughput RPS、error rate、latency），无数据时返回空序列
		istioNs := ""
		if namespace != "" {
			istioNs = fmt.Sprintf(`,destination_service_namespace="%s"`, namespace)
		}
		baseIstio := fmt.Sprintf(`{reporter="destination"%s}`, istioNs)
		qRps := fmt.Sprintf(`sum(rate(istio_requests_total%s[1m]))`, baseIstio)
		// 5xx 错误率：5xx 请求数 / 总请求数，分母为 0 时用 1 避免除零
		qErrorRate := fmt.Sprintf(`sum(rate(istio_requests_total{reporter="destination",response_code=~"5.."%s}[1m])) / (sum(rate(istio_requests_total%s[1m])) or vector(1))`, istioNs, baseIstio)
		qP50 := fmt.Sprintf(`histogram_quantile(0.50, sum(rate(istio_request_duration_milliseconds_bucket%s[1m])) by (le))`, baseIstio)
		qP95 := fmt.Sprintf(`histogram_quantile(0.95, sum(rate(istio_request_duration_milliseconds_bucket%s[1m])) by (le))`, baseIstio)
		qP99 := fmt.Sprintf(`histogram_quantile(0.99, sum(rate(istio_request_duration_milliseconds_bucket%s[1m])) by (le))`, baseIstio)
		resp.Rps, _ = queryPrometheusRange(base, qRps, start, end, step)
		resp.ErrorRate, _ = queryPrometheusRange(base, qErrorRate, start, end, step)
		resp.LatencyP50, _ = queryPrometheusRange(base, qP50, start, end, step)
		resp.LatencyP95, _ = queryPrometheusRange(base, qP95, start, end, step)
		resp.LatencyP99, _ = queryPrometheusRange(base, qP99, start, end, step)

		resp.Available = true
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}
