### demo演示

以istio的bookinfo示例服务为例，演示部署Kmesh后进行百分比灰度访问的执行过程；

- 启动Kmesh

  ```sh
  [root@vm-x86-11222]# systemctl start kmesh.service
  ```

- bookinfo环境准备

  部署istio及启动bookinfo的流程可参考[bookinfo环境部署](https://istio.io/latest/docs/setup/getting-started/)；需要注意的是，无需为namespace注入`istio-injection` 标记，即不需要启动istio的数据面代理程序；

  因此准备SAIHIEQIjksbak好的环境上关注如下信息：

  ```sh
  # default ns未设置istio的sidecar注入
  [root@vm-x86-11222 networking]# kubectl get namespaces --show-labels
  NAME              STATUS   AGE   LABELS
  default           Active   92d   <none>
  ```

- 访问bookinfo

  ```sh
  [root@vm-x86-11222 networking]# productpage_addr=`kubectl get svc -owide | grep productpage | awk {'print $3'}`
  [root@vm-x86-11222 networking]# curl http://$productpage_addr:9080/productpage
  ```

- demo演示

  demo演示了基于Kmesh，对bookinfo的reviews服务实施百分比路由规则，并成功访问；

  ![demo_bookinfo_v1_v2_8_2](pics/demo_bookinfo_v1_v2_8_2.svg)
