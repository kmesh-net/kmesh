# Authorization Policy

The Dashboard configures access control via Istio **AuthorizationPolicy**, supporting L4 conditions such as IP, port, and namespace.

## Entry

**Authorization** menu → **Policy List** / **Configure Authorization** / **Custom YAML**.

## Policy List

- Lists AuthorizationPolicies in the selected namespace.
- Table columns: Name, Action (ALLOW/DENY), Target Workload, Rules Detail, Rules Count.
- Delete supported.

## Configure Authorization

- **Action**: ALLOW or DENY.
- **Target Workload**: Specify workload via selector.
- **Rules**: Configure from (source) and to (target operation) conditions.
  - Source: IP blocks, namespaces, Principals, etc.
  - Target: Ports, Hosts, paths, HTTP methods, etc.

## Support

Kmesh supports Istio AuthorizationPolicy with L4 conditions (IP, port, namespace). PeerAuthentication (mTLS) and RequestAuthentication (JWT) are planned for future releases.

## Custom YAML

- **Authorization** nav → **Custom YAML**: Create/update AuthorizationPolicy via YAML editor.
- Supports extra fields not exposed in the Dashboard.
