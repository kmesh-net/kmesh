# Kmesh命令说明

- kmesh-daemon

```sh
# kmesh-daemon -h
Start kmesh daemon

Usage:
  kmesh-daemon [flags]

Flags:
      --bpf-fs-path string     bpf fs path (default "/sys/fs/bpf")
      --cgroup2-path string    cgroup2 path (default "/mnt/kmesh_cgroup2")
      --enable-mda             enable mda
  -h, --help                   help for kmesh-daemon
      --mode string            controller plane mode, valid values are [kernel-native, dual-engine] (default "dual-engine")
      --monitoring string      enable kmesh traffic monitoring in daemon process(default "true")  
      --profiliing string      whether to enable profiling or not (default "false")
      --enable-ipsec string    enable ipsec encryption and authentication between nodes(default false)

# example
./kmesh-daemon --mode=kernel-native
# example
./kmesh-daemon --mode=dual-engine
# example
./kmesh-daemon --mode=kernel-native --enable-mda
# example
./kmesh-daemon --mode=dual-engine --enable-mda
  ```

- 运维相关

  kmesh-daemon在`localhost:15200`上提供管理接口（实现见`pkg/status/status_server.go`）。该接口仅监听环回地址，因此需要在Kmesh daemon Pod内访问，或先通过`kubectl port-forward`将端口转发到本机。推荐使用[`kmeshctl`](../../ctl/kmeshctl.md)操作这些接口。

  | Method | Path | 用途 |
  | --- | --- | --- |
  | GET | `/version` | 查看kmesh-daemon版本信息 |
  | GET | `/debug/ready` | 就绪探针，管理接口可用时返回`OK` |
  | GET | `/debug/loggers` | 列出日志scope；带`?name=<scope>`时查看指定scope的日志级别（特殊scope `bpf`控制BPF程序日志） |
  | POST | `/debug/loggers` | 设置日志级别，请求体为`{"name": "<scope>", "level": "<level>"}` |
  | GET | `/debug/config_dump/kernel-native` | 导出kernel-native模式下的配置缓存 |
  | GET | `/debug/config_dump/dual-engine` | 导出dual-engine模式下的workload、service和授权策略 |
  | GET | `/debug/config_dump/bpf/kernel-native` | 导出kernel-native模式下的BPF map配置 |
  | GET | `/debug/config_dump/bpf/dual-engine` | 导出dual-engine模式下的BPF map配置 |
  | POST | `/monitoring?enable=<bool>` | 开启或关闭流量监控（同时联动access log、workload metrics和connection metrics） |
  | POST | `/accesslog?enable=<bool>` | 开启或关闭access log |
  | POST | `/workload_metrics?enable=<bool>` | 开启或关闭workload metrics |
  | POST | `/connection_metrics?enable=<bool>` | 开启或关闭connection metrics |
  | POST | `/authz?enable=<bool>` | 开启或关闭基于XDP的授权卸载 |
  | GET | `/debug/pprof/` | Go pprof性能分析入口（还包括`/debug/pprof/cmdline`、`/debug/pprof/profile`、`/debug/pprof/symbol`、`/debug/pprof/trace`） |

  ```sh
  # 将Kmesh daemon Pod的管理端口转发到本机
  kubectl port-forward -n kmesh-system <kmesh-pod> 15200:15200

  # 示例：查看版本信息
  curl http://localhost:15200/version

  # 示例：导出dual-engine模式下的配置
  curl http://localhost:15200/debug/config_dump/dual-engine

  # 示例：将default日志scope的级别设置为debug
  curl -X POST http://localhost:15200/debug/loggers -d '{"name": "default", "level": "debug"}'
  ```

- 命令使用注意事项

  - `-bpf-fs-path`参数指定的`path`要求是bpf文件系统路径；如：

    ```sh
    [root@localhost Kmesh]# mount | grep "/sys/fs/bpf"
    none on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,relatime,mode=700)
    ```
