# Metrics Dashboard

The Dashboard fetches metrics from **Prometheus** and displays Kmesh L4 monitoring data (cumulative values) on the Metrics page.

## Entry

**Metrics** menu → Service Mesh Metrics.

## Data Source and Coverage

- Backend connects to Prometheus via **PROMETHEUS_URL** env (e.g. `export PROMETHEUS_URL=http://prometheus.kmesh-system:9090`). When not set, the page shows "Prometheus not configured" and does not query.
- Dashboard shows **cumulative values** (`sum(metric)`); no ongoing traffic needed for non-zero data:
  1. **Kmesh L4 Workload Metrics**
     - `kmesh_tcp_workload_connections_opened_total`, `kmesh_tcp_workload_connections_closed_total`
     - `kmesh_tcp_workload_received_bytes_total`, `kmesh_tcp_workload_sent_bytes_total`
     - `kmesh_tcp_workload_conntections_failed_total` (note typo)
  2. **Kmesh L4 Service Metrics**
     - `kmesh_tcp_connections_opened_total`, `kmesh_tcp_connections_closed_total`
     - `kmesh_tcp_received_bytes_total`, `kmesh_tcp_sent_bytes_total`
     - `kmesh_tcp_conntections_failed_total`

## Page Features

- **Namespace**: Optional; empty means aggregate all namespaces.
- **Refresh**: Reload current metrics.
- **Sections**:
  - **Workload Metrics**: Connections opened/closed/failed total, bytes received/sent total
  - **Service Metrics**: Connections opened/closed/failed total, bytes received/sent total
  - **Accesslog**: Filter accesslog from kmesh daemon pod logs (direct K8s, no Prometheus)

## Accesslog

Accesslog is fetched via K8s Pod Logs API, no Prometheus. Run `kmeshctl monitoring --accesslog enable` to enable accesslog output.

## Dependencies

- **Metrics**: Prometheus must be deployed; Kmesh must have telemetry enabled and report TCP metrics to Prometheus.
- **Accesslog**: K8s cluster must be accessible; kmesh pods are in the kmesh-system namespace.
