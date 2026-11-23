# Rate Limit Configuration

The Dashboard injects `envoy.filters.network.local_ratelimit` via Istio **EnvoyFilter** for connection-level local rate limiting (Token Bucket), aligned with the Kmesh proposal.

## Entry

**Rate Limit** menu → **Policy List** / **Configure Rate Limit**.

## Policy List

- Lists all EnvoyFilters containing local_ratelimit (filterable by namespace).
- Table columns: Namespace, Name, StatPrefix, Max Tokens, Tokens Per Fill, Fill Interval (s), Target (workload label or "All").
- Delete supported; list shows "applied" rate limit rules.

## Configure Rate Limit

- **Namespace**: EnvoyFilter namespace, usually same as the workload to be rate-limited.
- **EnvoyFilter Name**: Resource name, e.g. `filter-local-ratelimit-svc`.
- **Stat Prefix**: Optional, default `local_rate_limit`.
- **Target**: Optional. Select a service from the current namespace; its name is used as the workload `app` label to rate limit only that workload. If not selected, applies to all matching listeners (with tcp_proxy) in the namespace.
- **Token Bucket**:
  - **max_tokens**: Max tokens in bucket (burst limit).
  - **tokens_per_fill**: Tokens added per fill.
  - **fill_interval (seconds)**: Fill interval. E.g. 60 means add tokens_per_fill every 60 seconds.
- After apply, appears in **Policy List**; optionally observe in topology/metrics (e.g. connections rejected, 429).

## Dependencies

- Cluster must have Istio `networking.istio.io/v1alpha3` EnvoyFilter CRD.
- Current implementation is **connection-level** local rate limit (TCP listener with local_ratelimit), not HTTP QPS.
