# Cluster Nodes

## Overview

The Cluster Nodes page displays basic information and status of all nodes in the current Kubernetes cluster.

## Fields

- **Node Name**: Name of the node in the cluster
- **Status**: Node readiness (Ready / NotReady)
- **Roles**: Node roles (e.g. control-plane, worker)
- **Internal IP**: Internal IP address of the node
- **Age**: Node uptime
- **Kernel**: Kernel version
- **OS Image**: Operating system image

## Usage

1. Click **Cluster Nodes** in the top navigation
2. Click **Refresh** to reload the node list
3. Data is sourced from the cluster pointed to by the current kubeconfig
