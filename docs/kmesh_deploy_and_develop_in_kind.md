# Kmesh Deploy and Develop in Kind

[Kind](https://github.com/kubernetes-sigs/kind) is a convenient tool for quickly deploying kubernetes cluster locally. We can use `kind` to create an `istio` cluster and deploy `kmesh` on it.

## Deploy Kmesh in Kind

Let's start from setting up the required environment. You can follow the steps below:

+ Install `kind`:

    Installing `kind` is very simple, because it's just a binary file. You can select the correct one according to the version and the architecture in the [github releases page](https://github.com/kubernetes-sigs/kind/releases). Take `linux` + `amd64` as example:

    ```shell
    wget -O kind https://github.com/kubernetes-sigs/kind/releases/download/v0.23.0/kind-linux-amd64
    chmod +x kind
    mv kind /usr/bin/
    ```

+ Create Kubernetes cluster using `kind`:

    You can take reference from the [istio official document](https://istio.io/latest/docs/setup/platform-setup/kind/).

    If you want to specified multiple workers or node image, you can:

    ```shell
    kind create cluster --image=kindest/node:v1.23.17 --config=- <<EOF
    kind: Cluster
    apiVersion: kind.x-k8s.io/v1alpha4
    name: ambient
    nodes:
    - role: control-plane
    - role: worker
    - role: worker
    EOF
    ```

+ Install `istioctl`:

    ```shell
    curl -L https://istio.io/downloadIstio | sh -
    cd istio-1.22.2/bin
    chmod +x istioctl
    mv istioctl /usr/bin/
    ```

+ Install istio components using `istioctl`

    ```shell
    istioctl install
    ```

    If you want to use `kmesh` in `workload` mode, you should deploy `istio` in [ambient mode](https://istio.io/latest/docs/ambient/overview/), by adding an extra flag:

    ```shell
    istioctl install --set profile=ambient 
    ```

+ Install kubectl

    Please follow the official guide: [Install and Set Up kubectl on Linux](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/).

+ Deploy Kmesh

    Now, you are ready to deploy kmesh in your local cluster. Feel free to follow the [Kmesh Quick Start](https://kmesh.net/en/docs/setup/quickstart/).


## Develop Kmesh in Kind

You can follow the steps below to develop in kind:

+ Build your code locally:

    ```shell
    make build
    ```

    This will start a docker container named `kmesh-build` to build your code. 

+ Build your docker image locally:

    ```shell
    docker build --build-arg arch=amd64 -f build/docker/kmesh.dockerfile -t $image_name .
    ```

    You should specify the `image_name`.

+ Load the image to each cluster node

    ```shell
    kind load docker-image $image_name --name $cluster_name
    ```

    You should specify the `image_name` and `cluster_name`.

+ Edit the kmesh daemonset:

    Kmesh daemons are run as kubernetes `Daemonset`. You should modify the config of the daemonset, triggering a re-deployment.

    ```shell
    kubectl edit ds kmesh -n kmesh-system
    ```

    This will open an editor, you can modify the image here.

    You can check whether kmesh daemons are all running by:

    ```shell
    kubectl get po -n kmesh-system -w
    ```

+ Check logs

    You can check the logs of a kmesh daemon by:

    ```shell
    kubectl logs $kmesh_pod_name -n kmesh-system
    ```

    `kmesh_pod_name` is the name of a specified kmesh pod.

    You can change the logger level by:

    ```shell
    kubectl exec -it $kmesh_pod_name -n kmesh-system -- kmesh-daemon log --set default:debug
    ```

    Specially, for bpf logs:
    ```shell
    kubectl exec -it $kmesh_pod_name -n kmesh-system -- kmesh-daemon log --set bpf:debug
    ```

    You can use `uname -r` to check your kernel version. If it's higher than `5.13.0`, the bpf logs will be pushed to the user space. We can check them in the log file (with `subsys=ebpf`). Otherwise, you should use `bpftool` to check them:

    ```
    bpftool prog tracelog
    ```

+ Cleanup

    The build process will modify some config-related files, if you want to push your code to github, please use:

    ```shell
    make clean
    ```

    to cleanup this changes before you execute `git add` command.

## Reference
+ Getting Started: https://istio.io/latest/docs/ambient/getting-started/
+ Get Started with Istio Ambient Mesh
: https://istio.io/latest/blog/2022/get-started-ambient/
+ Install with Istioctl: https://istio.io/latest/docs/setup/install/istioctl/