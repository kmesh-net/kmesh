# Service Topology

## Overview

The Service Topology page provides a **link** to open Kiali in a new window for viewing service dependencies, traffic flow, and health status.

## Configuration

Set the `KIALI_URL` environment variable to a browser-accessible Kiali address, for example:

```bash
export KIALI_URL=http://kiali.kmesh-system:20001
```

When not configured, the topology page will show "Kiali not configured".

## Usage

1. After logging into the Dashboard, click **Service Topology** in the sidebar
2. Click **Open Kiali** to open Kiali in a new window
