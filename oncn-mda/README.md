## 介绍

mda(mesh data accelerate)是一种基于内核sockmap技术实现的，用于service mesh场景下同节点上socket通信加速的特性。

## 原理

sockmap是BPF程序的一种map类型，使用这种map可以存储sock的引用信息，从而实现一种加速本机内部TCP socket之间数据转发的机制。

主要原理涉及两段BPF程序：
第一段：当系统中有socket操作时（ACTIVE ESTABLISTED和PASSIVE ESTABLISTED），触发sock_ops hook执行，提取socket信息，并以key&value的形式存储到sockmap中；
第二段：拦截sendmsg系统调用，从消息中提取key，并根据key查询sockmap中记录的对端socket信息，然后通过bpf_socket_redirect_hash绕过TCP/IP协议栈，将数据包重定向到对端sock的收包队列。

## 配置文件设计

配置文件中配置需以chain开始，后跟如下选项：

1. --ip 地址范围，例如 192.168.1.0/24
2. --port 端口范围，例如 80
3. --uid-owner，用户所属uid组，例如1337
4. --gid-owner，用户所属gid组
5. -j，接受或者返回，可选值：ACCEPT或者RETURN

配置示例：

```text
# 仅加速192.168.1.0/24网段连接中的包含1337 uid的进程流量（包括正向建链与反向建链），对于连接双端包含有15006端口的流量禁止加速
chain --ip 192.168.1.0/24 --uid-owner 1337 --j ACCEPT
chain --port 15006 -j RETURN

```

## Kmesh服务下使用

前提条件：

* 系统中已配置好对应版本的软件repo源。
* 系统中至少已挂载一个cgroupv2路径目录。
* 系统中已挂载bpf文件系统。
* root用户。

### 安装Kmesh软件包

```shell
[root@openEuler ~]# yum install Kmesh
```

### Kmesh服务启动与停止

```shell
# service配置，将ExecStart配置设为如下形式
[root@openEuler ~]# vim /usr/lib/systemd/system/kmesh.service
ExecStart=/usr/bin/kmesh-daemon -enable-mda
[root@openEuler ~]# systemctl daemon-reload

# service启动
[root@dev ~]# systemctl start kmesh.service

# service停止
[root@dev ~]# systemctl stop kmesh.service
```

## 约束限制

* 运行时需要200M以上内存空间。
* 最大支持15000个并发连接。
* 只支持在同一台vm主机上服务网格中的ipv4 tcp的数据转发流，不支持控制数据流（建立连接，断开连接）。
* 使能加速能力后创建的数据连接才会被加速，已经建立的连接不会被加速。
* 加速后因为短接了部分底层内核网络协议栈，会对基于底层内核网络协议栈的特性产生影响。
* 加速链路建立完成后，socket之间通信不再受iptables的管控，修改iptables规则不会影响已经建立的链路。
* 对cgroupv2的使用仅限于满足网格加速程序的正确运行，不能用作其他用途。
* 启用该特性后，会在对应的系统调用上挂hook点，导致执行路径变长，造成跨主机的tcp吞吐下降10%-20%。
* 使能规则后，应用程序需要正确处理socket系统调用的返回错误码。例如对于大流量应用程序，客户端可能会存在返回错误EAGAIN的错误码，说明此时接收服务端缓存被占满，需要服务端将消息从缓冲区读出后客户端应用程序才能继续发送。

## 性能提升说明

本特性为加速特性，主要加速体现在对本机的ipv4 tcp连接的传输性能上。实验室测试场景如下：

* 主机使用4核、4G内存的虚拟机，虚机上仅运行k8s集群。
* 部署k8s集群，并安装云原生网络服务网格软件istio及其代理envoy。
* 在/etc/oncn-mda/oncn-mda.conf配置文件中，设置过滤参数为空并启动网格加速。
* 压测工具使用fortio，客户端与服务端在一台虚拟机上的两个容器中的场景下，连接数30-150，压测60s。

测试结果：top90（90%的请求完成时间）同主机节点间降低10%-15%，qps提升10%-15%。
