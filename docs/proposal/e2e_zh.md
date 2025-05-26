---
title: Kmesh E2E 测试框架
authors:
- "@YaoZengzeng"
reviewers:
- "@robot"
- TBD
approvers:
- "@robot"
- TBD

creation-date: 2024-06-19

---

## Kmesh E2E 测试框架

### 摘要

本提案主要介绍在 Kmesh 中引入 E2E 测试的动机、框架选择的权衡、框架的主要工作流程和测试用例分析。

### 动机

E2E 测试是一种软件方法，它测试应用程序从开始到结束的工作流程，模拟真实的用户场景。E2E 测试的主要目的是验证整个系统，确保所有单独的组件和集成无缝地协同工作。它有助于识别应用程序不同组件之间交互可能产生的任何问题或缺陷，确保应用程序在正常运行条件下按预期工作。

我们在开发过程中经常遇到这种情况：尽管所有的 UT 都通过了，但是当我们把代码编译成二进制文件，把组件部署到测试环境，甚至更糟糕的是，部署到生产环境时，我们发现一些基本功能不能工作了，而且不可用的原因显然不是由这次修改引起的。显然，每次合并代码之前手动测试所有场景是不现实的。

因此，我们在 Kmesh 中引入了 E2E 测试。在每个 PR 合并之前，代码修改必须被编译成二进制文件，部署到测试环境并通过所有基本测试。这确保了现有的功能不会因为新合并的代码而变得不可用。E2E 测试与 UT 相结合，从多个维度确保了项目的健壮性。

### 目标

确保每次代码合并都不会破坏现有功能，并确保 Kmesh 的稳定性和可用性。

### 提案

#### E2E 测试框架的选择

Kmesh E2E 测试框架在架构和代码上都深受 [istio 集成框架](https://github.com/istio/istio/tree/master/tests/integration) 的启发。使用它的优点和缺点如下：

优点：

1. 避免重复造轮子：istio 集成框架已经封装了很多基本功能，并且有一个完整的工作流程，例如部署本地镜像仓库、k8s 集群和 istio。我们可以很容易地调用它来避免繁琐的开发。只需在工作流程的适当位置插入 Kmesh 的编译和部署即可。

2. 完善的测试用例：istio 集成框架已经包含大量的测试用例，可以直接使用或修改以满足 istio 的一致性。

缺点：

1. 复杂性：经过多年的发展，istio 集成框架已经包含了许多功能，其中许多功能可能暂时不会使用。因此，会有一个陡峭的学习曲线，并且必须对其进行适当的裁剪才能在 Kmesh 中使用。

#### Kmesh E2E 框架的工作流程

![arch](./pics/e2e-arch.png)

1. 安装必要的依赖项。例如，我们使用 kind 来部署 istio 和 Kmesh，所以我们需要安装它。

2. 设置 k8s 集群。使用 kind 部署 k8s 集群非常方便，但应该注意的是，需要修改一些配置以允许从本地镜像仓库拉取镜像。

3. 准备一个本地镜像仓库。实际上它是一个 docker 容器，并且我们也应该进行一些配置以允许从主机和 kind 集群访问它。

4. 基于 PR 的代码更改编译并构建一个新的 Kmesh 镜像，并将其推送到本地仓库。

注意：以上所有步骤都由脚本实现，位于 [这里](/test/e2e/run_test.sh)

5. 使用 istio 集成框架的内置函数快速部署 istio。同时，istio 集成框架也提供了良好的可扩展性，方便我们部署 Kmesh 和一系列测试应用程序。

注意：此步骤基于 istio 集成框架在 [这里](/test/e2e/main_test.go) 实现。

6. 基于一系列已部署的测试应用程序编写各种测试用例。我们可以将它们写在 [这里](/test/e2e/baseline_test.go) 或在必要时创建一个新文件。

#### 测试用例分析

istio 集成框架已经很好地封装了，我们可以使用内置函数轻松创建各种配置的测试应用程序。我们可以按照以下流程创建测试用例：

1. 使用 [namespace](https://github.com/istio/istio/blob/master/pkg/test/framework/components/namespace/namespace.go) 包来创建命名空间，用于部署测试应用程序。

2. 使用 [deployment](https://github.com/istio/istio/blob/master/pkg/test/framework/components/echo/deployment/builder.go) 包来构建测试应用程序。`WithClusters()` 可用于指定应在其中部署测试应用程序的集群。每次调用 `WithConfig()` 将生成一个具有相应配置的测试应用程序。实际上，我们在开始时创建所有测试应用程序。在每个测试用例中，我们选择一些合适的应用程序进行测试。一个应用程序可以同时用作客户端和服务器。如果现有应用程序不符合您的要求，您可以调用 `WithConfig()` 创建一个具有不同配置的新测试应用程序，然后在您的测试用例中过滤掉该应用程序。我们相信 `echo` 包可以满足大多数场景。如果不能，您也可以编写一些自定义代码来部署特定的应用程序。

3. 每个测试用例将所有测试应用程序成对组合，并且还允许应用程序访问自身。使用 [echo](https://github.com/istio/istio/blob/master/pkg/test/framework/components/echo/calloptions.go) 包的 `CallOptions` 来定义调用 Endpoint 的选项，例如指定用于访问的协议、请求的数量以及 `Checker`，[echo](https://github.com/istio/istio/blob/master/pkg/test/framework/components/echo/checker.go) 包中定义的 `Checker` 也可以自定义访问是否成功。

4. Istio 集成框架使用起来非常方便。我们只需要进行适当的配置，甚至不需要担心测试应用程序底层是如何工作的。它还提供了直接应用 yamls 来创建资源（如 `VirtualService` 和 `DestinationRule`）的方法。

#### 用法

我们可以通过调用脚本 `./test/e2e/run_test.sh` 来运行 E2E 测试。完整的 E2E 测试包括以下步骤：

1. 安装依赖项，例如 kind、helm、istioctl ...
2. 将本地镜像仓库部署为 docker 容器，构建 Kmesh 镜像并推送到它
3. 部署 k8s 集群、istio 和 Kmesh
4. 部署测试应用程序并实际运行 E2E 测试用例

对于 Github CI 环境，以上所有步骤都应完整执行。但是当在本地测试时，我们经常希望跳过其中的一些步骤。我们提供以下标志来跳过测试的某些步骤：

- `--skip-install-dep`:      跳过安装依赖项
- `--skip-build`:            跳过部署本地镜像仓库和构建 Kmesh 镜像
- `--skip-setup`:            跳过部署 k8s、istio 和 Kmesh
- `--only-run-tests`:        跳过所有其他步骤，仅部署测试应用程序并运行 E2E 测试

例如，如果我们想在本地重复运行 E2E 测试，那么除了第一次，后续执行可以使用以下命令，避免不必要的下载和构建：

```bash
./test/e2e/run_test.sh --only-run-tests
```
注意：由于 Kmesh E2E 测试框架仍在快速发展，请参阅 [官方文档](https://kmesh.net/en/docs/developer/e2e-guide/) 以获取更完整和最新的用法。

