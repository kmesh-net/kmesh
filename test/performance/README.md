# Kmesh performance test

## Basic test networking

![perf_network](../../docs/pics/perf_network.png)

## Test tool

Fortio and dstat are used as performance test tools for Kmesh. Fortio is a powerful microservice load test library that can collect statistics on latency and throughput information such as TP90, TP99, and QPS. dstat is a system information statistics tool. It is used to collect the CPU usage during the test.

## Test Case Description

The directory contains a group of test case configuration and script files, which are used to test the performance of kmesh and industry software in the Kubernetes cluster environment.


### Environment Prepare：

- k8s cluster

- install istio

  - Download and install istio. For details, see (https://istio.io/latest/zh/docs/setup/getting-started/).

  ```sh
  $ curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.14.5 TARGET_ARCH=x86_64 sh -
  $ cd istio-1.14.5
  $ export PATH=$PWD/bin:$PATH
  $ istioctl install 
  ```


### Test Case Description：

There are eight tests, each of which contains the following sub-items: config and shell directories;

config: configuration file for starting the fortio pod and svc configuration file

shell: test script for automated test cases

#### big_small_test

This test case is used to test the performance in the case of multiple concurrent requests. Multiple Fortio clients or servers are started on the same node, and the resources used by one Fortio are changed. (For example, if the number of threads is changed, the CPU usage and memory usage will change.) to observe the impact on the performance of other Fortio traffic sending tests.

#### density_test

This test case is a density test. That is, multiple Fortio clients are deployed on the same node to perform a load test on the Fortio cluster. The number of Fortio-clients is changed. Collect system resource usage (CPU and memory usage) and load test result statistics (delay and QPS information).

In this test case, multiple fortio-clients are started at the same time, traffic is sent to the SVC port on each client, and performance information of different clients is observed.

#### multiple

When Nginx is used to forward packets for multiple times (multi-hop), check the system resource usage and load statistics, and test the traffic sending delay and QPS information.

#### qps_test

Test the system resource usage (CPU and memory usage) and load statistics in different QPSs.

#### bookinfo_test

When bookinfo functions as the backend, test the system resource usage and load statistics of different threads, and test the delay and QPS of traffic sending.

#### long_test

Test the system resource usage, load statistics, delay, and QPS of persistent connection in different threads.

#### packet-size_test

Test the system resource usage, load statistics, delay, and QPS information under different HTTP packet sizes.

#### short_test

Test the system resource usage, load statistics, delay, and QPS of different threads in the case of short connections.

### Use Example

The persistent link test is used as an example.

Perform the test in the environment where K8S and istio have been deployed.

- istio(envoy) test
- cilium test
- istio(Kmesh) test

##### istio(envoy) test

istio-sidecar injection:

`kubectl label namespace default istio-injection=enabled --overwrite`

Start the fortio-client, server, and service:

`kubectl apply -f config/fortio-client.yaml`

`kubectl apply -f config/fortio-server.yaml`

`kubectl apply -f config/fortio-service.yaml`

run:

`sh long_test.sh`

##### cilium test

Install Cillium: (This test does not require the participation of the iStio.)

```sh
# https://github.com/cilium/cilium-cli/releases，download cilium

cilium install --helm-set-string kubeProxyReplacement=strict --helm-set-string extraConfig enable-envoy-config=true
```

Start the fortio-client, server, and service:

`kubectl apply -f config/cilium_policy.yaml`

`kubectl apply -f config/fortio-client.yaml`

`kubectl apply -f config/fortio-server.yaml`

`kubectl apply -f config/fortio-service.yaml`

Run:

`sh long_test.sh`

##### kmesh test

Disable istio-sidecar injection:

`kubectl label namespace default istio-injection=unenabled --overwrite`

Start the fortio-client, server, and service:

`kubectl apply -f config/fortio-client.yaml`

`kubectl apply -f config/fortio-server.yaml`

`kubectl apply -f config/fortio-service.yaml`

start Kmesh:

Refer to [Quick Start](../../README.md#quick-start)

Run: 

`sh long_test.sh`

Create a folder in the current directory based on the time. Each thread has a file. You can view the execution result. The execution result includes the CPU and memory usage, Fortio traffic sending delay, and QPS information. You can compare the performance of kmesh with that of other packages.