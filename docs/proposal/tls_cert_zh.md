## 工作负载证书管理

### 概要

Kmesh支持TLS能力需要使用由istiod签发的证书，所以需要一套证书申请与管理模块，用于向istiod申请证书并管理证书的生命周期。

### 动机

Kmesh需要为纳管workload提供TLS能力，需要能够便捷的申请与管理证书，在合适的时机新增、删除、刷新证书

#### 目标

1. 为纳管workload所在的sa(service accont)申请证书
2. 证书有效期到期自动刷新

#### 非目标

1. 在ambient模式下，ztunnel与Kmesh各自拥有着一套证书管理体系，两者互不干扰，可能存在两者均为某sa申请了证书的情况，这种情况下流量被谁接管就使用谁的一套证书
2. Kmesh异常重启情况下，旧的证书记录全部废弃，证书全部重新申请，不考虑保留之前的证书

### 提议

实现一个证书申请模块和证书管理模块，其中

证书申请模块：与istod建立一个加密grpc连接，为纳管workload所在的sa(service accont)构造出CSR请求和对应的私钥，并使用CSR请求与istiod进行交互，由istiod进行签名后返回证书

证书管理模块：

- 管理需要对证书进行操作的时机入口：1、新增workload 2、删除workload 3、证书有效期到期自动刷新
- 管理证书的存放与管理方式
- 根据证书的有效期，在临近到期时触发对应证书的刷新任务

### 限制

当前如果需要使用Kmesh tls能力，需要在istio启动时，修改deployment，在`CA_TRUSTED_NODE_ACCOUNTS`环境变量后边添加`kmesh-system/kmesh `

## 设计细节

### 证书申请模块

随Kmesh启动创建一个caclient客户端，与istiod建立加密的grpc连接

使用workload中的信息，构造出CSR请求和私钥，将CSR请求通过caclient发送给istiod，istiod进行签名并返回证书

### 证书生命周期管理

使用一个通道、队列和map来记录和管理，其中队列和map均有锁来保证并发安全性

<div align="center">

![tls_cert_design](pics/tls_cert_design.svg)

</div>

**通道**：管理证书事件，根据Operation去处理证书任务，从通道中按序创建任务，可以防止一些并发调度问题

```go
chan ：用于接受所有证书相关事件
type certRequest struct {
	Identity  string
	Operation int
}
```

触发时机：

- 新增workload时
- 删除workload
- 证书到期，从队列中取出需要刷新的证书任务

**队列**：检查最近到期的证书，提前1小时刷新证书；

```go
队列元素内容：
type certExp struct {
    identity string	//使用sa构造的证书名
    exp time.Time	//证书到期时间
}
```

更新时机：
	新增证书：插入一条新的记录
	刷新证书：删除旧记录，添加新记录；
	删除证书：遍历并删除旧证书的记录

**map**：记录证书信息和证书状态

```go
map：记录使用该证书的pod 数量
​	key：Identity    //使用sa构造的证书名
​	value：certItem

type certItem struct {
	cert istiosecurity.SecretItem    //证书信息
    refcnt int32     //记录使用该证书的pod数
}
```

更新时机：
	在某sa下第一次有pod被Kmesh纳管时新增证书；新建并添加一条记录	
	在该sa下所有被Kmesh纳管pod都被删除时(refCnt=0)删除证书；删除一条记录

​	在证书到期自动刷新时更新value内容；刷新已有记录中的cert

​	在某sa下有pod被Kmesh纳管时，对应refcnt+1；
​	在某sa下有被Kmesh纳管的pod被删除时，对应refcnt-1；

生命周期：整个sa的证书存在的时间；创建于sa证书申请时，删除于sa证书删除时

#### 场景一：新增证书

<div align="center">

![tls_cert_scenario1](pics/tls_cert_scenario1.svg)

</div>

1. Kmesh纳管pod1，订阅到新增的workload，SecretManager查找对应sa的证书：若已存在则计数加1；若不存在则进行证书申请

2. 为sa1 构造并发送CSR请求

3. istiod签发证书

4. 存储证书：

   - 存储证书

   - 在状态信息中
     - 记录  count，为此sa进行计数，记录使用该证书的pod数量；

   - 往队列中添加一条到期时间的记录


#### 场景二：删除证书

<div align="center">

![tls_cert_scenario2](pics/tls_cert_scenario2.svg)

</div>

1. 删除pod1，删除对应workload

2. 该sa计数减一；

   若此时sa计数为0，则删除证书：

   - 遍历查找队列，删除对应的记录
   - 删除sa对应的证书


#### 场景三：证书到期自动更新

<div align="center">

![tls_cert_scenario3](pics/tls_cert_scenario3.svg)

</div>

1. 队列中有效期最近的证书到期，弹出该条记录，触发证书刷新动作
2. 为该证书的sa构造并发送CSR请求
3. istiod签发证书
4. 存储证书，

   - 刷新map中的证书；refcnt保持不变

- 在队列中添加该条记录

#### 特别设计：

map与队列均使用了锁来保证并发安全性，所有设计到map和队列的操作均使用定义的接口去进行操作，避免出现死锁等问题

由于申请证书需要通过grpc连接和istiod进行交互，耗时可能较大，而证书状态信息的变更为了并发安全性加了锁，所以在在需要新增或刷新证书时，需要把证书状态信息的变更和申请证书的流程分开：

例如：在新增证书的函数流程中，如果判断需要新申请证书，会先创建对应的状态信息记录并写入map，这样其他线程执行的时候就不会重复申请证书，随后等证书刷新下来之后再写入该条记录内，申请失败则删除这条记录；

### 遗留事项

1. 当前代码中的队列实现是优先队列，需要修改为普通队列，现有场景下按序从通道中获取证书事件，且Kmesh为workload申请的证书有效期一致，无需在队列中再排序
2. 纳管pod判断，目前Kmesh相关证书处理流程中无法判断workload是否被纳管，待后续实现
3. 某sa下只存在一个pod，该pod重启，引起workload快速删除与新增，会重复增删证书，带来不必要的开销，该场景需特殊处理

