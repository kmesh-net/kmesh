# Kmesh Deployment

## Helm

We provide a Helm Chart to deploy Kmesh in Kubernetes Cluster.

```bash
helm install kmesh ./deploy/charts/kmesh-helm -n kmesh-system --create-namespace
```

### Select an image version

The chart uses the `latest` Kmesh image by default. To install a specific
release image without editing the chart, set `deploy.kmesh.image.tag`. Choose
the tag for the release you want from the [Kmesh releases](https://github.com/kmesh-net/kmesh/releases).

```bash
# Replace <release-tag> with the image tag published for your chosen release.
helm install kmesh ./deploy/charts/kmesh-helm -n kmesh-system --create-namespace \
  --set-string deploy.kmesh.image.tag='<release-tag>'
```

Use the chart from the same release as the image to keep its configuration and
the Kmesh version compatible. The image tag override selects the container
image; it does not select or download a different chart version.

You can check the rendered image before installing:

```bash
helm template kmesh ./deploy/charts/kmesh-helm -n kmesh-system \
  --set-string deploy.kmesh.image.tag='<release-tag>'
```

## Yaml

We also support deploying using yaml files.

```bash
kubectl apply -f ./deploy/yaml/
```
