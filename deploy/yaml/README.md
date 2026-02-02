# Kmesh L7 EnvoyFilter Deployment

This directory contains EnvoyFilter configurations for Kmesh L7 (Layer 7) functionality.

## File Selection Based on Istio Version

Kmesh provides two different EnvoyFilter configurations to ensure compatibility across different Istio versions:

### For Istio 1.27 and later

Use **`l7-envoyfilter.yaml`**

This file uses the new `targetRefs` format introduced in Istio 1.26, which targets Gateway API resources directly.

```bash
kubectl apply -f l7-envoyfilter.yaml
```

### For Istio versions before 1.27

Use **`l7-envoyfilter-below-istio-1.27.yaml`**

This file uses the legacy `workloadSelector` format that targets pods by labels, compatible with Istio versions prior to 1.26.

```bash
kubectl apply -f l7-envoyfilter-below-istio-1.27.yaml
```

## How to Check Your Istio Version

```bash
istioctl version
```

or

```bash
kubectl get deploy -n istio-system istiod -o jsonpath='{.spec.template.spec.containers[0].image}' | cut -d':' -f2
```

## Key Differences

| Feature | l7-envoyfilter.yaml | l7-envoyfilter-below-istio-1.27.yaml |
| ------- | ------------------- | ------------------------------------ |
| **Istio Version** | 1.27+ (1.26+ compatible) | Before 1.27 |
| **Selector Type** | `targetRefs` | `workloadSelector` |
| **Target** | GatewayClass resource | Pod labels |
| **Recommendation** | Use for new deployments | Use for legacy compatibility |

## What These EnvoyFilters Do

Both files configure the same three EnvoyFilter resources:

1. **add-listener-filter**: Adds a custom listener on port 15019 for Kmesh traffic handling
2. **skip-tunneling**: Modifies TCP proxy filter to use the Kmesh original destination cluster
3. **add-original-dst-cluster**: Adds the Kmesh original destination cluster configuration

The only difference is the targeting mechanism used to apply these filters to the waypoint gateway.
