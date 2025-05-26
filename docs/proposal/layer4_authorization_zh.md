---
title: �� kmesh workload mod ��֧�� 4 ����Ȩ
authors:
- "@supercharge-xsy"
reviewers:
- "@hzxuzhonghu"
- "@nlwcy"
approvers:
- "@robot"
- TBD

creation-date: 2024-05-28
---
## �� workload ģʽ��֧�� L4 ��Ȩ

### ժҪ

����ּ�ڽ��� Kmesh ����� workload ģʽ��ʵ�� 4 ����Ȩ���ܡ��й���Ȩ���ܵĽ��ܣ���ο���[Kmesh TCP ��Ȩ](https://kmesh.net/en/docs/userguide/tcp_authorization/)��Ŀǰ��Kmesh ֧��������Ȩ�ܹ������ݰ�����ͨ�� XDP ��Ȩ���������֧�ָ����ͣ�����Ԫ����Ϣͨ�����λ����������Խ����û��ռ���Ȩ������Ŀ������ XDP ����ȫ������Ȩ��

### �û��ռ���Ȩ

#### ���ϸ��

![l4_authz](pics/kmesh_l4_authorization.svg#pic_center)

#### Map ����

```.c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct bpf_sock_tuple);
    __type(value, __u32); // init, deny, allow
    __uint(max_entries, MAP_SIZE_OF_AUTH);
} map_of_auth_result SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} map_of_auth_req SEC(".maps");


```

#### �����߼�

1. **sock-bpf:** �����ӽ��������У��ڷ������ˣ�sock bpf �߼��� established �׶α������������������ Kmesh ����
   - 1.1��Ԫ����Ϣ����¼�� `tuple_map` �У�����һ�����λ��������͵� map��Kmesh-daemon ����ʵʱ���ʡ�
   - 1.2��`auth_map` ��Ŀ����ʼ������ֵ����Ϊ `init`����ʾǨ����Ȩ���ڽ����С�
2. **kmesh-daemon:** kmesh-daemon ��������Ȩ����ƥ����Щ�����Խ�����Ȩ��顣
   - 2.1������ `tuple_map` �ж�ȡԪ���¼��һ����ȡ�����λ����� map �еļ�¼����ϵͳ�Զ������
   - 2.2�����ڶ�ȡ��Ԫ����Ϣ����ƥ����Ȩ��������� `allow`����������е� `init` ��¼������� `deny`����ֵ�� `init` ˢ��Ϊ `deny`��
3. **xdp-bpf**: ���ͻ��˷�����Ϣ���ҷ��������յ���Ϣʱ��ͨ�� xdp bpf ����
   - 3.1����ʹ����Ԫ����Ϣƥ�� `auth_map` �е����ݡ�����ҵ�ƥ������ֵ����Ϊ `init`����ʾǨ����Ȩ��δ��ɣ�����ʱ��������Ϣ��
   - 3.2�����ƥ��ļ�¼��ʾ `value=deny`�����������Ϣ��־������������� RST ��Ϣ���������Ӧ�� `auth_map` ��¼�����δ�ҵ��κμ�¼�����ʾ������Ȩ����Ϣ��ͨ����
4. **�ͻ�������**: �ͻ��˳��Է�����һ����Ϣ�������ڷ������ѹر����ӣ��ͻ����յ���reset by peer���źţ����ر��Լ���ͨ����

### Xdp ��Ȩ

#### ���ϸ��

![l4_authz_xdp](pics/kmesh_l4_authorization_xdp.svg#pic_center)

#### Map ����

map_of_wl_policy: ��¼Ϊ workload ���õĲ��ԡ�

map_of_authz_policy: ��¼���Ե� authz ����

kmesh_tc_args: �洢 xdp_auth ��β�����ڼ���Ҫʹ�õĲ���

```.c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(wl_policies_v));
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAP_SIZE_OF_AUTH_POLICY);
} map_of_wl_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(Istio__Security__Authorization));
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAP_SIZE_OF_AUTH_POLICY);
} map_of_authz_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct bpf_sock_tuple));
    __uint(value_size, sizeof(struct match_context));
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, MAP_SIZE_OF_AUTH_TAILCALL);
} kmesh_tc_args SEC(".maps");
```

#### Istio ����ģ��

![istio_policy_module](pics/istio_policy_module.png#pic_center)

������ʾ�� istio �洢���ԵĽṹͼ��Istio ��Ȩģ��ͨ�� `Istio__Security__Authorization` ��Դǿ��ִ�в��ԡ��ڴ�ģ���У�workload �����������Թ�������������в����� OR ���㡣ÿ�����԰������ֹ�����Щ����Ҳ�����Ƶķ�ʽ���� OR ����������һ�������һ���ֽ�Ϊ����Ӿ䣬��Щ�Ӿ�ʹ�� AND �߼���������������ζ�ű������������Ӿ������Ϊ�ù�����Ч�����ÿ���Ӿ�������ƥ�������Ϊ OR ���㣬���������κ�ƥ���������Ϊ���Ӿ������㡣���Բ㻹������Ȩ�����������վ�����Ȩ����

#### �����߼�

![l4_authz_xdp](pics/kmesh_xdp_authz.jpg#pic_center)

�� XDP ��Ȩ��ʵ���У����� eBPF ��֤�����ֽ��������ƣ�������Ҫʹ�� eBPF �� tailcall ������ʵ�� XDP ��Ȩ���������̡�������������ͼ��ʾ��
���ȣ���������� xdp_authz���ڴ� eBPF �����У���Ȩ�������ڴ��е���ʼ��ַ����д�� kmesh_tc_args eBPF map��Ȼ�󽫽��� tail call �� policies_check eBPF ���򡣸ó���Ὣ����ͱ�Ҫ��Ϣд�� kmesh_tc_args eBPF map��Ȼ�󽫽��� tail call �� policy_check eBPF �����Լ���ض����Ӿ�������漰���� port_check �� ip_check ֮���ƥ���߼������ڵ�ǰ�� xdp ��Ȩ��֧�� ip �� port������� clause_check �������ù����У�����������κι��� namespace �� principle �Ĳ��ԣ����� tailcall �� xdp_shutdown_in_userspace eBPF prog��

![l4_authz_xdp_process](pics/kmesh_l4_authorization_match_chain.svg#pic_center)

1. ��Ϣ�����������ݰ�����������˵� XDP �����߼�ʱ�����������ݰ���Ԫ����Ϣ��Ȼ�����Ŀ�� IP �ҵ���Ӧ�Ĺ�������ʵ�����������ڸù������������õ���Ȩ����
2. ����ƥ�䣺��ͼ��ʾ��XDP ʵ����һ��ƥ�����߼������ȣ������ݶ˿���Ϣȷ���������Ǿܾ����ݰ����������Ǿܾ������������ݰ������̽�������������������ʹ�ú������õ�����һ��ƥ���߼������磬IP ƥ�䣩���ظ��˹��̣�ֱ�����е����һ�����ӡ�������ս���������򷵻� XDP\_PASS���������ݰ�ͨ���ں������ջת������������
