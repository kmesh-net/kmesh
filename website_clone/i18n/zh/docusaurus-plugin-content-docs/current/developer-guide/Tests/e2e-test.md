---
title: 运行 E2E 测试
sidebar_position: 2
---

端到端（E2E）测试是现代软件开发中的一个关键组成部分，旨在模拟用户在整个应用程序中的交互，以确保所有组件和集成能够无缝协作。通过引入 E2E 测试，我们可以验证代码更改不会干扰现有功能，从而在系统演进过程中保持其完整性和可靠性。

## 先决条件

用户需要安装以下组件：

- Go
- Docker
- Kubectl

以下组件将在使用 shell 脚本时自动安装：

- Kind
- Helm
- Istioctl

## 使用方法

要运行 E2E 测试，请执行位于 `./test/e2e` 目录中的 `run_test.sh` 脚本。该脚本将自动完成以下任务：

1. **安装依赖项：** 安装 Kind、Helm 和 Istioctl 等工具。
2. **部署本地镜像注册表：** 使用 Docker 容器作为本地镜像注册表。
3. **构建并推送 Kmesh 镜像：** 构建自定义 Kmesh Docker 镜像并将其推送到本地注册表。
4. **部署 Kubernetes 集群、Istio 和 Kmesh：** 这些组件是测试所需的，在此步骤中完成设置。
5. **部署测试应用程序并执行 E2E 测试。**

## 命令行标志

在本地测试时，您可能希望跳过某些设置步骤以节省时间，特别是在初始设置完成后。以下标志可用于自定义测试执行：

- **--skip-install-dep**：跳过依赖项的安装。
- **--skip-build**：跳过构建并推送 Kmesh 镜像到本地镜像注册表。
- **--skip-setup**：跳过部署 Kubernetes 集群、Istio 和 Kmesh。
- **--only-run-tests**：跳过所有其他步骤，仅专注于部署测试应用程序和运行 E2E 测试。
- **--cluster**：允许通过名称指定一个预先存在的 KinD 集群。
- **--ipv6**：启用创建具有 IPv6 网络的 KinD 集群并在其上运行 E2E 测试。
- **--cleanup**：在测试完成后清理 KinD 集群和本地注册表。
- **--skip-cleanup-apps**：在测试执行后跳过清理测试应用程序。
- 直接使用 **go test** 命令行参数运行测试

### 示例命令

#### 完整测试运行（首次）

```bash
./test/e2e/run_test.sh
```

使用此命令进行初始设置和测试运行，以确保所有配置正确。

#### 后续测试运行（跳过所有设置并仅运行测试）

```bash
./test/e2e/run_test.sh --only-run-tests
```

您可能需要不同类型的测试。

#### 指定一个预先存在的 KinD 集群

```bash
./test/e2e/run_test.sh --cluster <KinD-Cluster-Name>
```

#### 创建一个 IPv6 KinD 集群并运行测试

```bash
./test/e2e/run_test.sh --ipv6
```

在某些情况下，您可能希望在测试后清理某些资源，而在其他情况下，您可能希望跳过清理测试应用程序以供进一步使用。

#### 在测试后清理 KinD 集群和 Docker 注册表

```bash
./test/e2e/run_test.sh --cleanup
```

#### 在测试后跳过清理测试应用程序

```bash
./test/e2e/run_test.sh --skip-cleanup-apps
```

您还可以在运行测试时直接使用 **go test** 命令行参数。例如，您可以过滤特定的测试用例，或直接从命令行控制测试过程的其他方面。

#### 选择特定的测试用例

```bash
./test/e2e/run_test.sh --only-run-tests -run "TestServices"
```

#### 控制测试详细程度

```bash
./test/e2e/run_test.sh -v
```

#### 重复测试用例多次

```bash
./test/e2e/run_test.sh -count=3
```
