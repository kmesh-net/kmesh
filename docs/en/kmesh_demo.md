### Demo

The bookinfo service of istio is used as an example to demonstrate the percentage gray access process after Kmesh is deployed.

- Start Kmesh

  ```sh
  [root@vm-x86-11222]# systemctl start kmesh.service
  ```

- Bookinfo environment preparation

  For the process of deploying istio and starting bookinfo, See: [Bookinfo Environment Deployment](https://istio.io/latest/docs/setup/getting-started/), Note that you do not need to inject the `istio-injection` tag into the namespace, that is, you do not need to start the istio data plane agent.

  Therefore, pay attention to the following information in the prepared environment:

  ```sh
  # default ns not set sidecar injection of istio
  [root@vm-x86-11222 networking]# kubectl get namespaces --show-labels
  NAME              STATUS   AGE   LABELS
  default           Active   92d   <none>
  ```

- Access bookinfo

  ```sh
  [root@vm-x86-11222 networking]# productpage_addr=`kubectl get svc -owide | grep productpage | awk {'print $3'}`
  [root@vm-x86-11222 networking]# curl http://$productpage_addr:9080/productpage
  ```

- Demo demonstration

  The demo shows how to implement percentage routing rules for the reviews service of bookinfo based on Kmesh and successfully access the service.

  ![demo_bookinfo_v1_v2_8_2](pics/demo_bookinfo_v1_v2_8_2.svg)
