## 介绍

mda(mesh data accelerate)是一种基于内核sockmap技术实现的，用于service mesh场景下同节点上socket通信加速的特性。

## 原理
sockmap是BPF程序的一种map类型，使用这种map可以存储sock的引用信息，从而实现一种加速本机内部TCP socket之间数据转发的机制。

主要原理涉及两段BPF程序：
第一段：当系统中有socket操作时（ACTIVE ESTABLISTED和PASSIVE ESTABLISTED），触发sock_ops hook执行，提取socket信息，并以key&value的形式存储到sockmap中；
第二段：拦截sendmsg系统调用，从消息中提取key，并根据key查询sockmap中记录的对端socket信息，然后通过bpf_socket_redirect_hash绕过TCP/IP协议栈，将数据包重定向到对端sock的收包队列。

## 命令行设计

```shell
# 使能加速能力
mdacli enable

# 除能加速能力
mdacli disable

# 查询使能状态
mdacli query
```
## 配置文件设计

配置文件中配置需以chain开始，后跟如下选项：
1. --ip 地址范围，例如 192.168.1.0/24
2. --port 端口范围，例如 80
3. --uid-owner，用户所属uid组，例如1337
4. --gid-owner，用户所属gid组
5. -j，接受或者返回，可选值：ACCEPT或者RETURN

示例：
```
# 仅加速192.168.1.0/24网段连接中的包含1337 uid的进程流量（包括正向建链与反向建链），对于连接双端包含有15006端口的流量禁止加速
chain --ip 192.168.1.0/24 --uid-owner 1337 --j ACCEPT
chain --port 15006 -j RETURN

```
