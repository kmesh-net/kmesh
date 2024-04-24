## Quick Start

- prerequisite

  - Currently, Kmesh connects to the Istio control plane. Before starting Kmesh, install the Istio control plane software. For details, see https://istio.io/latest/docs/setup/getting-started/#install.

  - The complete Kmesh capability depends on the OS enhancement. Check whether the execution environment is in the [OS list](../docs/kmesh_support.md) supported by Kmesh. For other OS environments, see [Kmesh Compilation and Building](./kmesh_compile.md).You can also try the [kmesh image in compatibility mode](../build/docker/README.md) in other OS environments.For information on various Kmesh images, please refer to the [detailed document](../build/docker/README.md).
  
- Docker Images

  Kmesh achieves the ability to completely sink traffic management below the OS through kernel enhancements. When releasing images, the range of OS for which the image is applicable must be considered. To this end, we consider releasing three types of images:

  - Supported OS versions with kernel enhancement modifications

    The current [openEuler 23.03](https://repo.openeuler.org/openEuler-23.03/) OS natively supports the kernel enhancement features required by Kmesh. Kmesh release images can be directly installed and run on this OS. For a detailed list of supported OS versions with kernel enhancement modifications, please refer to [this link](https://github.com/kmesh-net/kmesh/blob/main/docs/kmesh_support.md).
  
  - For all OS versions:

    To be compatible with different OS versions, Kmesh provides online compilation and running images. After Kmesh is deployed, it will automatically select Kmesh features supported by the host machine's kernel capabilities, to meet the demand for one image to run in different OS environments.
    
    Considering the universality of kmesh, we have released an image for compiling and building kmesh. Users can conveniently create a kmesh image based on this, which can run on their current OS version. By default, it is named `ghcr.io/kmesh-net/kmesh:latest`, but the user can adjust it as needed. Please refer to [Kmesh Build Compilation](docs/kmesh_compile.md#build docker image) for more details.
    
    
    ```bash
    make docker TAG=latest
    ```
  
- Start Kmesh

  - Install from Helm
  
    ```sh
    [root@ ~]# helm install kmesh ./deploy/helm -n kmesh-system --create-namespace
    ```

  - Install from Yaml

    ```sh
    # get kmesh.yaml from deploy/yaml/kmesh.yaml
    [root@ ~]# kubectl apply -f kmesh.yaml
    [root@ ~]# kubectl apply -f clusterrole.yaml
    [root@ ~]# kubectl apply -f clusterrolebinding.yaml
    [root@ ~]# kubectl apply -f serviceaccount.yaml
    [root@ ~]# kubectl apply -f l7-envoyfilter.yaml
    ```
  
  By default, the Kmesh base function is used, other function can be selected by adjusting the startup parameters in the yaml file.
  
- Check kmesh service status

  ```sh
  [root@ ~]# kubectl get pods -A | grep kmesh
  kmesh-system   kmesh-l5z2j                                 1/1     Running   0          117m
  ```

- View the running status of kmesh service

  ```sh
  [root@master mod]# kubectl logs -f -n kmesh-system kmesh-l5z2j
  time="2024-02-19T10:16:52Z" level=info msg="service node sidecar~192.168.11.53~kmesh-system.kmesh-system~kmesh-system.svc.cluster.local connect to discovery address istiod.istio-system.svc:15012" subsys=controller/envoy
  time="2024-02-19T10:16:52Z" level=info msg="options InitDaemonConfig successful" subsys=manager
  time="2024-02-19T10:16:53Z" level=info msg="bpf Start successful" subsys=manager
  time="2024-02-19T10:16:53Z" level=info msg="controller Start successful" subsys=manager
  time="2024-02-19T10:16:53Z" level=info msg="command StartServer successful" subsys=manager
  time="2024-02-19T10:16:53Z" level=info msg="start write CNI config\n" subsys="cni installer"
  time="2024-02-19T10:16:53Z" level=info msg="kmesh cni use chained\n" subsys="cni installer"
  time="2024-02-19T10:16:54Z" level=info msg="Copied /usr/bin/kmesh-cni to /opt/cni/bin." subsys="cni installer"
  time="2024-02-19T10:16:54Z" level=info msg="kubeconfig either does not exist or is out of date, writing a new one" subsys="cni installer"
  time="2024-02-19T10:16:54Z" level=info msg="wrote kubeconfig file /etc/cni/net.d/kmesh-cni-kubeconfig" subsys="cni installer"
  time="2024-02-19T10:16:54Z" level=info msg="command Start cni successful" subsys=manager
  ```
  
  More compilation methods of Kmesh, See: [Kmesh Compilation and Construction](./kmesh_compile.md)

- Deploy the sample application
  - Add default namespace to Kmesh

    ```
    [root@ ~]# kubectl label namespace default istio.io/dataplane-mode=Kmesh
    [root@ ~]# kubectl get namespace -L istio.io/dataplane-mode
    NAME                 STATUS   AGE   DATAPLANE-MODE
    default              Active   13d   Kmesh
    istio-system         Active   13d   
    kmesh-system         Active   27h   
    kube-node-lease      Active   13d   
    kube-public          Active   13d   
    kube-system          Active   13d   
    local-path-storage   Active   13d   
    ```
 
  - Deploy bookinfo

    ```
    [root@ ~]# kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.21/samples/bookinfo/platform/kube/bookinfo.yaml
    ```

  - Deploy sleep as curl client

    ```
    [root@ ~]# kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.21/samples/sleep/sleep.yaml
    [root@ ~]# kubectl get pods
    NAME                             READY   STATUS    RESTARTS   AGE
    details-v1-5f4d584748-bz42z      1/1     Running   0          72s
    productpage-v1-564d4686f-2rjqc   1/1     Running   0          72s
    ratings-v1-686ccfb5d8-dnzkf      1/1     Running   0          72s
    reviews-v1-86896b7648-fqm4z      1/1     Running   0          72s
    reviews-v2-b7dcd98fb-nn42q       1/1     Running   0          72s
    reviews-v3-5c5cc7b6d-q4r5h       1/1     Running   0          72s
    sleep-9454cc476-86vgb            1/1     Running   0          62s
    ```

  - Test boofinfo works as expected

    ```
    [root@ ~]# kubectl exec deploy/sleep -- curl -s http://productpage:9080/ | grep -o "<title>.*</title>"
    <title>Simple Bookstore App</title>
    ```

- Kmesh L7

  - Deploy a waypoint for service account `bookinfo-reviews`, so any traffic to service `reviews` will be mediated by that waypoint proxy

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
  
  - Replace the waypoint image with the Kmesh customized image. Based on istio-proxy, Kmesh adds an customized listener filter called [kmesh_tlv](https://github.com/kmesh-net/waypoint/tree/master/source/extensions/filters/listener/kmesh_tlv) to connect L4 and L7.

    ```
    [root@ ~]# kubectl get gateways.gateway.networking.k8s.io
    NAME               CLASS            ADDRESS         PROGRAMMED   AGE
    bookinfo-reviews   istio-waypoint   10.96.207.125   True         8m36s
    ```

    Add annotation "sidecar.istio.io/proxyImage: ghcr.io/kmesh-net/waypoint-{arch}:v0.3.0" to the `bookinfo-reviews` gateway, convert `{arch}` to the architecture of the host, current optional values are `x86` and `arm`. Then gateway pod will restart. Now kmesh is L7 enabled!

  - Configure traffic routing to send 90% of requests to `reviews` v1 and 10% to `reviews` v2

    ```
    [root@ ~]# kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.21/samples/bookinfo/networking/virtual-service-reviews-90-10.yaml
    [root@ ~]# kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.21/samples/bookinfo/networking/destination-rule-reviews.yaml
    ```

  - Confirm that roughly 90% of the traffic go to `reviews` v1

    ```
    [root@ ~]# kubectl exec deploy/sleep -- sh -c "for i in \$(seq 1 100); do curl -s http:productpage:9080/productpage | grep reviews-v.-; done"
    ```
