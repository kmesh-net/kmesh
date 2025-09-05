## Step 1. 部署kmesh

## Step 2. 部署 fortio 和 httpbin

```yaml
apiVersion: v1
kind: Service
metadata:
  name: fortio
  labels:
    app: fortio
    service: fortio
spec:
  ports:
  - port: 8080
    name: http
  selector:
    app: fortio
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fortio-deploy
spec:
  replicas: 1
  selector:
    matchLabels:
      app: fortio
  template:
    metadata:
      annotations:
        # This annotation causes Envoy to serve cluster.outbound statistics via 15000/stats
        # in addition to the stats normally served by Istio. The Circuit Breaking example task
        # gives an example of inspecting Envoy stats via proxy config.
        proxy.istio.io/config: |-
          proxyStatsMatcher:
            inclusionPrefixes:
            - "cluster.outbound"
            - "cluster_manager"
            - "listener_manager"
            - "server"
            - "cluster.xds-grpc"
      labels:
        app: fortio
    spec:
      containers:
      - name: fortio
        image: fortio/fortio:latest_release
        imagePullPolicy: Always
        ports:
        - containerPort: 8080
          name: http-fortio
        - containerPort: 8079
          name: grpc-ping
```

```sh
kubectl apply -f sample/httpbin/httpbin.yaml
```

## Step 3. 为httpbin配置waypoint

```sh
kmeshctl waypoint apply -n default --name httpbin-waypoint
kubectl label service httpbin istio.io/use-waypoint=httpbin-waypoint
```

## Step 4. 配置destinationRule：

```sh
kubectl apply -f - <<EOF
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata:
  name: httpbin
spec:
  host: httpbin
  trafficPolicy:
    connectionPool:
      tcp:
        # 限制与目标服务的最大 TCP 连接数 
        maxConnections: 1
      http:
        # 限制 HTTP 请求的最大待处理请求数
        http1MaxPendingRequests: 1
        # 限制每个连接允许的最大请求数。
        maxRequestsPerConnection: 1
    outlierDetection:
      # 熔断设置
      consecutive5xxErrors: 1
      interval: 1s
      baseEjectionTime: 3m
      maxEjectionPercent: 100
EOF
```

## Step 5. 通过istioctl查看waypoint中cds的配置：

```sh
istioctl proxy-config all <waypoint-pod-name>
```

## Step 6. 通过fortio访问看实际的现象：

```sh
export FORTIO_POD=$(kubectl get pods -l app=fortio -o 'jsonpath={.items[0].metadata.name}')
kubectl exec "$FORTIO_POD" -c fortio -- /usr/bin/fortio load -c 5 -qps 0 -n 50 -loglevel Warning http://httpbin:8000/get
```