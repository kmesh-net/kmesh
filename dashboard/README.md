# 🚀 Kmesh Dashboard

> A modern, user-friendly dashboard for simplifying Service Mesh management in Kmesh.

## 📖 Overview

Kmesh Dashboard is an interactive web-based UI designed to reduce the operational complexity of managing Kmesh service mesh environments. It provides visual workflows, topology insights, policy management, and observability features to help developers and platform engineers manage service mesh configurations more efficiently.

This project is inspired by community feedback highlighting the steep learning curve associated with Kmesh operations such as waypoint configuration, traffic policy management, and Envoy filter customization.

The dashboard aims to provide a simplified experience through intuitive interfaces and guided workflows.

---

## ✨ Features

### 🛣️ Waypoint Management

- One-click waypoint installation
- Guided setup workflows
- Support for:
  - Namespace-level waypoints
  - Service-level waypoints
  - Workload-level waypoints
- Real-time deployment status and validation

### 🌐 Service Topology Visualization

- Interactive service dependency graph
- Traffic flow visualization
- Health status indicators
- Similar experience to Kiali topology view

### ⚙️ Traffic Management Policies

- Simplified Circuit Breaker configuration
- Preset policy templates
- Real-time validation
- Rate limiting policy builder
- Immediate feedback for applied configurations

### 📊 Observability & Metrics

- Service mesh performance dashboard
- Latency monitoring
- Error rate tracking
- Throughput visualization
- Integrated metrics view

### 🔐 Authentication & Security

- Built-in authentication support
- Role-Based Access Control (RBAC)
- Secure dashboard access

### 📚 Documentation

- User guides
- Setup instructions
- Feature walkthroughs
- Configuration examples

---

## 🛠️ Tech Stack

- ⚛️ **Frontend:** React + TypeScript
- ☸️ **Backend/API:** Kubernetes APIs
- 🌐 **Service Mesh:** Kmesh
- 📈 **Visualization:** D3.js / React Flow (planned)
- 🎨 **UI Framework:** TBD
- 🚢 **Deployment:** Kubernetes

---

## 🎯 Project Goals

The primary goals of this project are:

- ✅ Lower the barrier to adopting Kmesh
- ✅ Simplify complex service mesh operations
- ✅ Improve visibility into service communication
- ✅ Provide intuitive UX for developers and operators
- ✅ Reduce manual YAML and Envoy filter editing

---

## 🏗️ Architecture (Planned)

```text
+----------------------+
|   Kmesh Dashboard    |
|   React Frontend     |
+----------+-----------+
           |
           v
+----------------------+
|   Dashboard Backend  |
|  Kubernetes Client   |
+----------+-----------+
           |
           v
+----------------------+
|     Kubernetes       |
|       + Kmesh        |
+----------------------+
```

---

## 🚀 Getting Started

### 📋 Prerequisites

- Kubernetes cluster
- Kmesh installed
- kubectl configured
- Node.js >= 18
- npm or pnpm

### 📥 Clone Repository

```bash
git clone https://github.com/<your-username>/kmesh-dashboard.git
cd kmesh-dashboard
```

### 📦 Install Dependencies

```bash
npm install
```

### ▶️ Start Development Server

```bash
npm run dev
```

---

## 🗺️ Roadmap

- [ ] 🎨 Initial dashboard UI
- [ ] ☸️ Kubernetes integration
- [ ] 🛣️ Waypoint management workflows
- [ ] 🌐 Topology visualization
- [ ] ⚙️ Circuit breaker UI
- [ ] 🚦 Rate limiting builder
- [ ] 📊 Metrics dashboard
- [ ] 🔐 Authentication & RBAC
- [ ] 📦 Helm chart deployment
- [ ] 📚 Documentation website

---

## 🤝 Contributing

Contributions are welcome and appreciated! 🎉

If you'd like to contribute:

1. 🍴 Fork the repository
2. 🌱 Create a feature branch
3. 💾 Commit your changes
4. 🔃 Open a pull request

Please follow coding standards and include documentation for new features.

---

## 🔗 Related Links

- Kmesh Project: <https://github.com/kmesh-net/kmesh>
- Upstream Issue: <https://github.com/kmesh-net/kmesh/issues/1552>

---

## 📄 License

This project is licensed under the Apache License 2.0.

---

## 🚧 Status

> Work in Progress — actively under development 🚀
