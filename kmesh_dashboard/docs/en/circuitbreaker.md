# Circuit Breaker Configuration

The Dashboard configures circuit breaking and connection pooling via Istio **DestinationRule** `trafficPolicy.connectionPool`, aligned with Envoy/Kmesh proposal fields.

## Entry

**Circuit Breaker** menu → **Policy List** / **Configure Circuit Breaker**.

## Policy List

- Lists all DestinationRules with `connectionPool` in the cluster (filterable by namespace).
- Table columns: Namespace, Name, Target Host, Max Connections, Max Pending Requests, Max Requests, Max Retries, Connect Timeout, Max Requests Per Connection.
- Delete supported.

## Configure Circuit Breaker

- **Preset templates**: Conservative (low thresholds), Standard, Aggressive (high thresholds); selection auto-fills values.
- **Custom**: When no template is selected, fill thresholds manually.
- **Required**: Namespace, DestinationRule name, Target Host (service name, e.g. `reviews`, `httpbin.default.svc.cluster.local`).
- **Optional thresholds** (aligned with proposal):
  - **maxConnections**: TCP max connections
  - **http1MaxPendingRequests**: Max pending HTTP requests
  - **http2MaxRequests**: HTTP/2 max requests
  - **maxRetries**: Max retries
  - **connectTimeout**: Connect timeout (form uses ms)
  - **maxRequestsPerConnection**: Max requests per connection
- Frontend validates numeric ranges; on apply, writes to cluster DestinationRule (updates if exists).
- Cluster must have Istio `networking.istio.io/v1beta1` DestinationRule CRD installed, otherwise the API will error.
