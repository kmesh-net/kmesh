---
title: Integrating Kmesh into Headlamp UI
authors:
- "@gouravi19"
reviewers:
- TBD
approvers:
- TBD

creation-date: 2026-05-10

---

## Integrating Kmesh into Headlamp UI

### Summary

This proposal outlines the design and architecture for integrating Kmesh observability and management features into the [Headlamp](https://headlamp.dev/) Kubernetes UI. Based on guidance from Headlamp maintainers, this integration will be implemented as an **external Headlamp plugin** maintained within the Kmesh ecosystem, rather than contributing directly to the Headlamp core repository. This approach ensures decoupled release cycles, easier maintainability, and alignment with Headlamp's extensible architecture.

### Motivation

As Kmesh continues to grow as a high-performance service mesh based on eBPF, users need a seamless, intuitive graphical interface to visualize mesh topology, monitor workload health, and inspect traffic observability metrics. Headlamp is a highly extensible, user-friendly Kubernetes dashboard that provides an ideal platform for building these capabilities via its plugin system.

#### Goals

- Provide a rich, unified UI for observing and managing Kmesh within a Kubernetes cluster using Headlamp.
- Establish an external Headlamp plugin architecture that adheres to maintainer expectations (plugin logic lives outside the Headlamp core repo).
- Outline a phased, incremental roadmap for delivering Kmesh observability features (workload health, traffic, topology) without inventing unsupported APIs or new CRDs unnecessarily.
- Enhance the overall UX for Kmesh users by surfacing key metrics and status overviews natively within their cluster management dashboard.

#### Non-Goals

- Modifying the core Headlamp repository or its built-in components.
- Building a standalone Kmesh dashboard from scratch.
- Creating new, unsupported CRDs or backend APIs purely for the UI; the plugin should consume existing Kmesh/Kubernetes APIs and metrics.

### Proposal

We propose building the "Kmesh Headlamp Plugin" as an external plugin package. This plugin will hook into Headlamp's extension points (such as navigation menus, details pages, and cluster overview sections) to present Kmesh-specific data.

#### Architecture: External Plugin

Following the feedback from Headlamp maintainers, plugins are not expected to live directly inside the Headlamp core repository.

**Why keep logic outside the Headlamp core repo?**

1. **Decoupled Releases:** Kmesh and Headlamp have independent release cycles. An external plugin allows Kmesh UI updates to ship at the speed of Kmesh development.
2. **Maintainer Focus:** Headlamp maintainers avoid taking on the maintenance burden of domain-specific logic (like Kmesh eBPF specifics).
3. **Ecosystem Standard:** Headlamp's plugin architecture is specifically designed to allow dynamic loading of external plugins (distributed as container images or static assets).

The plugin source code will reside either in a dedicated repository (e.g., `kmesh-net/headlamp-plugin`) or a specific directory within the Kmesh repository if preferred by the maintainers, built into a standard Headlamp plugin format.

#### Proposed Dashboard Structure

The plugin will introduce the following UI elements to Headlamp:

1. **Sidebar Navigation:** A dedicated "Kmesh" section in the Headlamp sidebar.
2. **Kmesh Overview Page:** A high-level dashboard showing the health of the Kmesh daemonset, overall mesh traffic stats, and active Kmesh workloads.
3. **Workload/Pod Integrations:** Injecting Kmesh-specific tabs or health indicators into standard Kubernetes Pod/Deployment detail pages to quickly show if a workload is part of the mesh and its current traffic status.

### Design Details

#### Phased Roadmap for Implementation

To keep the implementation incremental and maintainable, we propose the following phased approach:

**Phase 1: Foundation & Overview (Current Focus)**

- Scaffold the external Headlamp plugin repository/directory structure using React and TypeScript.
- Implement the "Kmesh Overview" page.
- Display Kmesh DaemonSet status and basic cluster-wide Kmesh health.
- Add Kmesh to the Headlamp sidebar.

**Phase 2: Workload Observability & YAML Views**

- **Workload Health Cards:** Show specific Kmesh metrics (e.g., bypass status, injection status) on workload cards.
- **YAML/Resource Views:** Provide rich views for any Kmesh-specific configuration resources (e.g., routing rules, if managed via standard Kubernetes APIs or Gateway API).
- Embed Kmesh status indicators directly into the Headlamp Pod and Deployment detail views.

**Phase 3: Traffic & Topology (Future Ideas)**

- **Traffic Observability:** Visualize L4/L7 traffic metrics, latency, and error rates captured by Kmesh's eBPF datapath.
- **Topology Visualization:** A graphical node/edge view of how services are communicating through the mesh, similar to Kiali but integrated into Headlamp.
- **Cluster Status Overview:** Deeper integration with Headlamp's main cluster dashboard to highlight mesh health at a glance.

#### Open Questions / TODOs for Maintainers

> [!WARNING]
> Architecture Clarification Needed
> Before proceeding with deep implementation, we need feedback from Kmesh maintainers on the following:
>
> 1. **Plugin Repository Location:** Should the Headlamp plugin source code live in a new repository under the Kmesh organization, or within a specific folder (e.g., `ui/headlamp-plugin`) in this main Kmesh repository?
> 2. **Backend Metrics/API:** The plugin should avoid inventing unsupported APIs. For Phase 3 (Traffic & Topology), does Kmesh currently expose these metrics via standard Prometheus endpoints that the UI can query directly, or is an intermediate aggregator required?
> 3. **Distribution:** Headlamp plugins are typically distributed as OCI artifacts or init containers that inject static assets into the Headlamp pod. Are there specific CI/CD preferences for publishing this plugin artifact alongside Kmesh releases?

### Alternatives

- **Standalone UI:** Building a custom React application from scratch. *Rejected* because it requires users to deploy and manage yet another UI tool, whereas Headlamp is a popular, general-purpose dashboard that many users might already have.
- **Upstreaming to Headlamp:** *Rejected* based on explicit feedback from Headlamp maintainers that domain-specific plugins should remain external.
