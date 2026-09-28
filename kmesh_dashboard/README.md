# Kmesh Dashboard

Kmesh visual dashboard that lowers the usage barrier with an interactive UI. It supports Waypoint installation, service topology, circuit breaking/rate limiting configuration, metrics overview, and RBAC.

## Quick Start

### 1. Start the backend

The backend connects to the cluster pointed to by the current KUBECONFIG (or in-cluster configuration) and provides APIs such as `GET /api/cluster/nodes`.

```bash
cd kmesh_dashboard/backend
export KUBECONFIG=/path/to/your/kubeconfig   # Optional; if unset, use default or in-cluster config
export PROMETHEUS_URL=http://prometheus.kmesh-system:9090 # Optional; used by metrics page, UI will show unconfigured if unset
export KIALI_URL=http://kiali.kmesh-system:20001  # Optional; redirect URL for service topology page
go run ./cmd/server/
```

By default it listens on `:8080`; you can override it with the `PORT` environment variable.

### 2. Start the frontend

```bash
cd kmesh_dashboard/frontend
npm install
npm run dev
```

The frontend dev server runs at http://localhost:3000, and requests to `/api/*` are proxied to backend port 8080.

### 3. Usage

Open http://localhost:3000 in your browser. On the "Cluster Nodes" page you can view the Node list of the current Kmesh cluster (fetched from cluster APIs by the backend).