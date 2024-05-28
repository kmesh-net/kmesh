# Kmesh Deployment

## Helm

We provide a Helm Chart to deploy Kmesh in Kubernets Cluster.

```bash
helm install kmesh ./deploy/helm -n kmesh-system --create-namespace
```

## Yaml

We also support deploying using yaml files.

```bash
kubectl apply -f ./deploy/yaml/
```