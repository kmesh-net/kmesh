## 快速开始

- 前提条件

  - Kmesh当前是对接Istio控制面，启动Kmesh前，需要提前安装好Istio的控制面软件；具体安装步骤参考：https://istio.io/latest/docs/setup/getting-started/#install
  - 完整的Kmesh能力依赖对OS的增强，需确认执行环境是否在Kmesh支持的[OS列表](./kmesh_support-zh.md)中，对于其他OS环境需要参考[Kmesh编译构建](../docs/kmesh_compile-zh.md)；也可以使用[兼容模式的kmesh镜像](../build/docker/README.md#兼容模式镜像)在其他OS环境中进行尝试，关于kmesh各种镜像的说明请参考[详细文档](../build/docker/README.md)。
  
- Docker镜像：

  Kmesh实现通过内核增强将完整的流量治理能力下沉至OS。当发布镜像时，镜像适用的OS的范围是必须考虑的。因此，我们考虑发布三种类型的镜像：

  - 支持内核增强的OS版本：

    当前[openEuler 23.03](https://repo.openeuler.org/openEuler-23.03/)原生支持Kmesh所需的内核增强特性。Kmesh发布的镜像可以直接在该OS上安装运行。对于详细的支持内核增强的OS版本列表，请参见[链接](https://github.com/kmesh-net/kmesh/blob/main/docs/kmesh_support.md)。
  
  - 针对所有OS版本：

    为了兼容不同的OS版本，Kmesh提供在线编译并运行的镜像。在Kmesh被部署之后，它会基于宿主机的内核能力自动选择运行的Kmesh特性，从而满足一个镜像在不同OS环境运行的要求。
    
    考虑到kmesh使用的通用性，我们也发布了用于kmesh编译构建的镜像。用户可以基于此镜像方便的制作出可以在当前OS版本上运行的kmesh镜像。默认命名为ghcr.io/kmesh-net/kmesh:latest，用户可自行调整，参考[Kmesh编译构建](./kmesh_compile-zh.md#docker image编译)
  
    ```bash
    make docker TAG=latest
    ```
  
- 启动Kmesh容器

  默认使用名为 ghcr.io/kmesh-net/kmesh:latest的镜像，如需使用兼容模式或其他版本可自行修改

  - Helm安装方式
  
    ```sh
    [root@ ~]# helm install kmesh ./deploy/helm -n kmesh-system --create-namespace
    ```

  - Yaml安装方式
  
    ```sh
    # get kmesh.yaml：来自代码仓 deploy/yaml/kmesh.yaml
    [root@ ~]# kubectl apply -f kmesh.yaml
    [root@ ~]# kubectl apply -f clusterrole.yaml
    [root@ ~]# kubectl apply -f clusterrolebinding.yaml
    [root@ ~]# kubectl apply -f serviceaccount.yaml
    [root@ ~]# kubectl apply -f l7-envoyfilter.yaml
    ```
  
    默认使用Kmesh功能，可通过调整yaml文件中的启动参数进行功能选择
  
- 查看kmesh服务启动状态

  ```sh
  [root@ ~]# kubectl get pods -A | grep kmesh
  kmesh-system   kmesh-l5z2j                                 1/1     Running   0          117m
  ```

- 查看kmesh服务运行状态

  ```sh
  [root@master mod]# kubectl logs -f -n kmesh-system kmesh-l5z2j
  time="2024-02-19T10:16:52Z" level=info msg="service node sidecar~192.168.11.53~kmesh-system  kmesh-system~kmesh-system.svc.cluster.local connect to discovery address istiod.istio-system  svc:15012" subsys=controller/envoy
  time="2024-02-19T10:16:52Z" level=info msg="options InitDaemonConfig successful" subsys=manager
  time="2024-02-19T10:16:53Z" level=info msg="bpf Start successful" subsys=manager
  time="2024-02-19T10:16:53Z" level=info msg="controller Start successful" subsys=manager
  time="2024-02-19T10:16:53Z" level=info msg="command StartServer successful" subsys=manager
  time="2024-02-19T10:16:53Z" level=info msg="start write CNI config\n" subsys="cni installer"
  time="2024-02-19T10:16:53Z" level=info msg="kmesh cni use chained\n" subsys="cni installer"
  time="2024-02-19T10:16:54Z" level=info msg="Copied /usr/bin/kmesh-cni to /opt/cni/bin."  subsys="cni installer"
  time="2024-02-19T10:16:54Z" level=info msg="kubeconfig either does not exist or is out of date,  writing a new one" subsys="cni installer"
  time="2024-02-19T10:16:54Z" level=info msg="wrote kubeconfig file /etc/cni/net.d  kmesh-cni-kubeconfig" subsys="cni installer"
  time="2024-02-19T10:16:54Z" level=info msg="command Start cni successful" subsys=manager
  ```
  
  更多Kmesh编译构建方式，请参考[Kmesh编译构建](./kmesh_compile-zh.md)

- Kmesh L7

  - 为service account `bookinfo-reviews` 部署一个waypoint，这样所有发往service `reviews` 的流量都将被这个waypoint proxy接管

    ```
    [root@ ~]# istioctl x waypoint apply --service-account bookinfo-reviews
    [root@ ~]# kubectl get pods
    NAME                                               READY   STATUS    RESTARTS   AGE
    bookinfo-reviews-istio-waypoint-5d544b6d54-v5tc9   1/1     Running   0          4s
    details-v1-5f4d584748-bz42z                        1/1     Running   0          4m35s
    productpage-v1-564d4686f-2rjqc                     1/1     Running   0          4m35s
    ratings-v1-686ccfb5d8-dnzkf                        1/1     Running   0          4m35s
    reviews-v1-86896b7648-fqm4z                        1/1     Running   0          4m35s
    reviews-v2-b7dcd98fb-nn42q                         1/1     Running   0          4m35s
    reviews-v3-5c5cc7b6d-q4r5h                         1/1     Running   0          4m35s
    sleep-9454cc476-86vgb                              1/1     Running   0          4m25s
    ```

  - 用kmesh自定义的镜像替换waypoint的原生镜像。基于istio-proxy，Kmesh增加了一个名为[kmesh_tlv](https://github.com/kmesh-net/waypoint/tree/master/source/extensions/filters/listener/kmesh_tlv)的自定义listener filter用于连接L4和L7

    ```
    [root@ ~]# kubectl get gateways.gateway.networking.k8s.io
    NAME               CLASS            ADDRESS         PROGRAMMED   AGE
    bookinfo-reviews   istio-waypoint   10.96.207.125   True         8m36s
    ```

    在`bookinfo-reviews` gateway的annotations当中添加sidecar.istio.io/proxyImage: ghcr.io/kmesh-net/waypoint-{arch}:v0.3.0，将{arch}转换为所在宿主机的架构，当前可选的取值为x86和arm。在gateway pod重启之后，kmesh就具备L7能力了！

  - 配置流量路由，将90%的请求发往`reviews` v1并且将其余的10%发往`reviews` v2

    ```
    [root@ ~]# kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.21/samples/bookinfo/networking/virtual-service-reviews-90-10.yaml
    [root@ ~]# kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.21/samples/bookinfo/networking/destination-rule-reviews.yaml
    ```

  - 确认大概90%的流量发往了`reviews` v1

    ```
    [root@ ~]# kubectl exec deploy/sleep -- sh -c "for i in \$(seq 1 100); do curl -s http:productpage:9080/productpage | grep reviews-v.-; done"
    ```
