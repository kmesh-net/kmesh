//go:build integ
// +build integ

/*
 * Copyright The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// NOTE: THE CODE IN THIS FILE IS MAINLY REFERENCED FROM ISTIO INTEGRATION
// FRAMEWORK(https://github.com/istio/istio/tree/master/tests/integration)
// AND ADAPTED FOR KMESH.

package kmesh

import (
	"fmt"
	"istio.io/istio/pkg/test/echo/common/scheme"
	"istio.io/istio/pkg/test/framework"
	"os/exec"
	"testing"
	"time"

	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/check"
)

// 等待所有dst的XDP程序加载
func waitForXDPOnDstWorkloads(t framework.TestContext, dst echo.Instances) {
	count := 0
	workloads := dst.WorkloadsOrFail(t)
	namespace := apps.Namespace.Name()
	for _, client := range workloads {
		if count == len(workloads) {
			break
		}
		podName := client.PodName()
		timeout := time.After(5 * time.Second)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
	InnerLoop:
		for {
			select {
			case <-timeout:
				t.Fatalf("Timeout: XDP eBPF program not found on pod %s", podName)
			case <-ticker.C:
				cmd := exec.Command("kubectl", "exec", "-n", namespace, podName, "--", "sh", "-c", "ip a | grep xdp")
				output, err := cmd.CombinedOutput()
				if err == nil && len(output) > 0 {
					t.Logf("XDP program is loaded on pod %s", podName)
					count++
					break InnerLoop
				}
				t.Logf("Waiting for XDP program to load on pod %s: %v", podName, err)
			}
		}
	}
}

func TestIPAuthorization(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		t.NewSubTest("IP Authorization").Run(func(t framework.TestContext) {
			// Enable authorizaiton offload to xdp.

			if len(apps.ServiceWithWaypointAtServiceGranularity) == 0 {
				t.Fatal(fmt.Errorf("need at least 1 instance of apps.ServiceWithWaypointAtServiceGranularity"))
			}
			src := apps.ServiceWithWaypointAtServiceGranularity[0]

			clients := src.WorkloadsOrFail(t)
			dst := apps.EnrolledToKmesh

			addresses := clients.Addresses()
			if len(addresses) < 2 {
				t.Fatal(fmt.Errorf("need at least 2 clients"))
			}
			selectedAddress := addresses[0]

			authzCases := []struct {
				name string
				spec string
			}{
				{
					name: "allow",
					spec: `
  action: ALLOW
`,
				},
				{
					name: "deny",
					spec: `
  action: DENY
`,
				},
			}

			chooseChecker := func(action string, ip string) echo.Checker {
				switch action {
				case "allow":
					if ip != selectedAddress {
						return check.NotOK()
					} else {
						return check.OK()
					}
				case "deny":
					if ip != selectedAddress {
						return check.OK()
					} else {
						return check.NotOK()
					}
				default:
					t.Fatal("invalid action")
				}

				return check.OK()
			}
			// 等待XDP程序加载
			waitForXDPOnDstWorkloads(t, dst)

			for _, tc := range authzCases {
				t.ConfigIstio().Eval(apps.Namespace.Name(), map[string]string{
					"Destination": dst.Config().Service,
					"Ip":          selectedAddress,
				}, `apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: ip-policy
spec:
  selector:
    matchLabels:
      app: "{{.Destination}}"
`+tc.spec+`
  rules:
  - from:
    - source:
        ipBlocks:
        - "{{.Ip}}"
`).ApplyOrFail(t)

				for _, client := range clients {
					opt := echo.CallOptions{
						To:                      dst,
						Port:                    echo.Port{Name: "tcp"},
						Scheme:                  scheme.TCP,
						NewConnectionPerRequest: true,
						// Due to the mechanism of Kmesh L4 authorization, we need to set the timeout slightly longer.
						Timeout: time.Minute * 2,
					}

					var name string
					if client.Address() != selectedAddress {
						name = tc.name + ", not selected address"
					} else {
						name = tc.name + ", selected address"
					}

					opt.Check = chooseChecker(tc.name, client.Address())

					t.NewSubTestf("%v", name).Run(func(t framework.TestContext) {
						src.WithWorkloads(client).CallOrFail(t, opt)
					})
				}
			}
		})
	})
}

func TestPortAuthorization(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		t.NewSubTest("Port Authorization").Run(func(t framework.TestContext) {
			// Enable authorization offload to xdp.

			if len(apps.ServiceWithWaypointAtServiceGranularity) == 0 {
				t.Fatal(fmt.Errorf("need at least 1 instance of apps.ServiceWithWaypointAtServiceGranularity"))
			}
			src := apps.ServiceWithWaypointAtServiceGranularity[0]

			clients := src.WorkloadsOrFail(t)
			client := clients[0]
			dst := apps.EnrolledToKmesh

			// 定义测试端口 - 使用 Pod 端口
			selectedPodPort := "19090"    // 被策略选中的 Pod 端口（对应 Service 端口 9090）
			notSelectedPodPort := "16060" // 未被策略选中的 Pod 端口（对应 Service 端口 9091）

			// Echo Pod 的健康检查端口
			readyPort := "8080"    // ready 端口
			livenessPort := "3333" // liveness 端口

			authzCases := []struct {
				name  string
				spec  string
				ports string
			}{
				{
					name: "allow",
					spec: `  action: ALLOW`,
					// ALLOW策略：允许selectedPodPort、ready端口和liveness端口
					ports: fmt.Sprintf(`["%s", "%s", "%s"]`, selectedPodPort, readyPort, livenessPort),
				},
				{
					name: "deny",
					spec: `  action: DENY`,
					// DENY策略：只拒绝selectedPodPort端口
					ports: fmt.Sprintf(`["%s"]`, selectedPodPort),
				},
			}

			chooseChecker := func(action string, servicePort int) echo.Checker {
				switch action {
				case "allow":
					if servicePort == 9090 { // selectedPodPort 对应的 Service 端口
						return check.OK() // ALLOW策略下，selectedPodPort应该成功
					} else {
						return check.NotOK() // ALLOW策略下，其他端口应该失败
					}
				case "deny":
					if servicePort == 9090 { // selectedPodPort 对应的 Service 端口
						return check.NotOK() // DENY策略下，selectedPodPort应该失败（被拒绝）
					} else {
						return check.OK() // DENY策略下，其他端口应该成功
					}
				default:
					t.Fatal("invalid action")
				}

				return check.OK()
			}

			// 测试用例：访问不同的 Service 端口
			portTestCases := []struct {
				servicePort int    // Service 端口
				podPort     string // 对应的 Pod 端口
				description string
			}{
				{
					servicePort: 9090,
					podPort:     selectedPodPort,
					description: fmt.Sprintf("service port 9090 (pod port %s)", selectedPodPort),
				},
				{
					servicePort: 9091,
					podPort:     notSelectedPodPort,
					description: fmt.Sprintf("service port 9091 (pod port %s)", notSelectedPodPort),
				},
			}

			// 等待XDP程序加载
			waitForXDPOnDstWorkloads(t, dst)

			for _, tc := range authzCases {
				t.ConfigIstio().Eval(apps.Namespace.Name(), map[string]string{
					"Destination": dst.Config().Service,
					"Ports":       tc.ports, // 使用 Pod 端口配置策略
				}, `apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: port-policy
spec:
  selector:
    matchLabels:
      app: "{{.Destination}}"
`+tc.spec+`
  rules:
  - to:
    - operation:
        ports: {{.Ports}}
`).ApplyOrFail(t)

				for _, portTest := range portTestCases {
					opt := echo.CallOptions{
						To:                      dst,
						Port:                    echo.Port{Name: "tcp", ServicePort: portTest.servicePort}, // 使用 Service 端口测试
						Scheme:                  scheme.TCP,
						NewConnectionPerRequest: true,
						// Due to the mechanism of Kmesh L4 authorization, we need to set the timeout slightly longer.
						Timeout: time.Minute * 2,
					}

					var name string
					name = tc.name + ", " + portTest.description

					opt.Check = chooseChecker(tc.name, portTest.servicePort)

					t.NewSubTestf("%v", name).Run(func(t framework.TestContext) {
						src.WithWorkloads(client).CallOrFail(t, opt)
					})
				}
			}
		})
	})
}

func TestNamespaceAuthorization(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		t.NewSubTest("Namespace Authorization").Run(func(t framework.TestContext) {
			// Enable authorization offload to xdp.

			if len(apps.ServiceWithWaypointAtServiceGranularity) == 0 {
				t.Fatal(fmt.Errorf("need at least 1 instance of apps.ServiceWithWaypointAtServiceGranularity"))
			}
			src := apps.ServiceWithWaypointAtServiceGranularity[0]

			clients := src.WorkloadsOrFail(t)
			client := clients[0]
			dst := apps.EnrolledToKmesh

			// 获取apps的namespace
			selectedNamespace := apps.Namespace.Name()

			authzCases := []struct {
				name string
				spec string
			}{
				{
					name: "allow",
					spec: `
  action: ALLOW
`,
				},
				{
					name: "deny",
					spec: `
  action: DENY
`,
				},
			}

			chooseChecker := func(action string) echo.Checker {
				switch action {
				case "allow":
					return check.OK()
				case "deny":
					return check.NotOK()
				default:
					t.Fatal("invalid action")
				}

				return check.OK()
			}
			// 等待XDP程序加载
			waitForXDPOnDstWorkloads(t, dst)

			for _, tc := range authzCases {
				t.ConfigIstio().Eval(apps.Namespace.Name(), map[string]string{
					"Destination":     dst.Config().Service,
					"SourceNamespace": selectedNamespace, // apps的namespace
				}, `apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: namespace-policy
spec:
  selector:
    matchLabels:
      app: "{{.Destination}}"
`+tc.spec+`
  rules:
  - from:
    - source:
        namespaces:
        - "{{.SourceNamespace}}"
`).ApplyOrFail(t)

				opt := echo.CallOptions{
					To:                      dst,
					Port:                    echo.Port{Name: "tcp"},
					Scheme:                  scheme.TCP,
					NewConnectionPerRequest: true,
					// Due to the mechanism of Kmesh L4 authorization, we need to set the timeout slightly longer.
					Timeout: time.Minute * 2,
				}

				var name string
				name = tc.name + ", namespace " + selectedNamespace

				opt.Check = chooseChecker(tc.name)

				t.NewSubTestf("%v", name).Run(func(t framework.TestContext) {
					src.WithWorkloads(client).CallOrFail(t, opt)
				})

			}
		})
	})
}

func TestHeaderAuthorization(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		t.NewSubTest("Header Authorization").Run(func(t framework.TestContext) {
			// Enable authorization offload to xdp.

			if len(apps.ServiceWithWaypointAtServiceGranularity) == 0 {
				t.Fatal(fmt.Errorf("need at least 1 instance of apps.ServiceWithWaypointAtServiceGranularity"))
			}
			src := apps.EnrolledToKmesh[0] // 使用已注册到Kmesh的应用

			clients := src.WorkloadsOrFail(t)
			client := clients[0]
			dst := apps.ServiceWithWaypointAtServiceGranularity

			// 定义测试的header和端口 - 使用pod端口
			selectedHeaderName := "x-api-key"
			selectedHeaderValue := "secret-token"
			targetHttpPodPort := 18080  // 目标HTTP Pod端口
			targetHttpServicePort := 80 // 对应的Service端口
			readyPort := 8080           // ready端口 - 不被拦截
			livenessPort := 3333        // liveness端口 - 不被拦截
			denyPort := 80              // 被拒绝的端口 - 不被拦截

			authzCases := []struct {
				name string
				spec string
			}{
				{
					name: "allow",
					spec: `
  action: ALLOW
`,
				},
				{
					name: "deny",
					spec: `
  action: DENY
`,
				},
			}

			chooseChecker := func(action string, headerMatches bool) echo.Checker {
				switch action {
				case "allow":
					if !headerMatches {
						return check.NotOK() // ALLOW策略下，header不匹配应该失败
					} else {
						return check.OK() // ALLOW策略下，header匹配应该成功
					}
				case "deny":
					if !headerMatches {
						return check.OK() // DENY策略下，header不匹配应该成功（不被拒绝）
					} else {
						return check.NotOK() // DENY策略下，header匹配应该失败（被拒绝）
					}
				default:
					t.Fatal("invalid action")
				}

				return check.OK()
			}

			// 测试用例：匹配的header和不匹配的header
			headerTestCases := []struct {
				headerValue string
				matches     bool
				description string
			}{
				{
					headerValue: selectedHeaderValue, // "secret-token"
					matches:     true,
					description: "matching header",
				},
				{
					headerValue: "wrong-token", // 错误的token
					matches:     false,
					description: "non-matching header",
				},
			}

			// 等待XDP程序加载
			waitForXDPOnDstWorkloads(t, dst)

			for _, tc := range authzCases {
				var additionalRule string

				// 总是允许健康检查端口，不受header策略影响
				if tc.name == "allow" {
					additionalRule = fmt.Sprintf(`
  - to:                                    # 规则1：总是允许健康检查端口（不受header限制）
    - operation:
        ports: ["%d", "%d", "%d"]`, readyPort, livenessPort, targetHttpPodPort)
				} else {
					additionalRule = fmt.Sprintf(`
  - to:                                    # 规则1：随意设置一个端口，避免所有tcp端口被拒绝
    - operation:
        ports: ["%d"]`, denyPort)
				}

				t.ConfigIstio().Eval(apps.Namespace.Name(), map[string]string{
					"Destination":   dst.Config().Service,
					"HeaderName":    selectedHeaderName,
					"HeaderValue":   selectedHeaderValue,
					"TargetPodPort": fmt.Sprintf("%d", targetHttpPodPort), // 使用Pod端口
				}, `apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: header-policy
spec:
  selector:
    matchLabels:
      app: "{{.Destination}}"
`+tc.spec+`
  rules:`+additionalRule+`
  - when:
    - key: request.headers[{{.HeaderName}}]
      values: ["{{.HeaderValue}}"]
`).ApplyOrFail(t)

				for _, headerTest := range headerTestCases {
					opt := echo.CallOptions{
						To:     dst,
						Port:   echo.Port{Name: "http", ServicePort: targetHttpServicePort}, // 使用Service端口80测试
						Scheme: scheme.HTTP,                                                 // Header需要HTTP协议
						HTTP: echo.HTTP{
							Path: "/api/test",
							Headers: map[string][]string{
								selectedHeaderName: {headerTest.headerValue}, // 动态设置header值
							},
						},
						NewConnectionPerRequest: true,
						// Due to the mechanism of Kmesh L4 authorization, we need to set the timeout slightly longer.
						Timeout: time.Minute * 2,
					}

					var name string
					name = fmt.Sprintf("%s, %s on service port %d (pod port %d)", tc.name, headerTest.description, targetHttpServicePort, targetHttpPodPort)

					opt.Check = chooseChecker(tc.name, headerTest.matches)

					t.NewSubTestf("%v", name).Run(func(t framework.TestContext) {
						src.WithWorkloads(client).CallOrFail(t, opt)
					})
				}
			}
		})
	})
}

func TestHostAuthorization(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		t.NewSubTest("Host Authorization").Run(func(t framework.TestContext) {
			// Enable authorization offload to xdp.

			if len(apps.ServiceWithWaypointAtServiceGranularity) == 0 {
				t.Fatal(fmt.Errorf("need at least 1 instance of apps.ServiceWithWaypointAtServiceGranularity"))
			}
			src := apps.EnrolledToKmesh[0] // 使用已注册到Kmesh的应用

			clients := src.WorkloadsOrFail(t)
			client := clients[0]
			dst := apps.ServiceWithWaypointAtServiceGranularity

			// 获取app的第一个host值
			selectedHost := "example.com" // 假设这是app的第一个host值
			targetHttpPodPort := 18080  // 目标HTTP Pod端口
			targetHttpServicePort := 80 // 对应的Service端口
			readyPort := 8080           // ready端口 - 不被拦截
			livenessPort := 3333        // liveness端口 - 不被拦截
			denyPort := 80              // 被拒绝的端口 - 不被拦截

			authzCases := []struct {
				name string
				spec string
			}{
				{
					name: "allow",
					spec: `
  action: ALLOW
`,
				},
				{
					name: "deny",
					spec: `
  action: DENY
`,
				},
			}

			// 测试用例：匹配的host和不匹配的host
			hostTestCases := []struct {
				hostValue   string
				matches     bool
				description string
			}{
				{
					hostValue:   selectedHost, // 正确的host
					matches:     true,
					description: "matching host",
				},
				{
					hostValue:   "wrong.example.com", // 错误的host
					matches:     false,
					description: "non-matching host",
				},
			}

			chooseChecker := func(action string, hostMatches bool) echo.Checker {
				switch action {
				case "allow":
					if !hostMatches {
						return check.NotOK() // ALLOW策略下，host不匹配应该失败
					} else {
						return check.OK() // ALLOW策略下，host匹配应该成功
					}
				case "deny":
					if !hostMatches {
						return check.OK() // DENY策略下，host不匹配应该成功（不被拒绝）
					} else {
						return check.NotOK() // DENY策略下，host匹配应该失败（被拒绝）
					}
				default:
					t.Fatal("invalid action")
				}

				return check.OK()
			}

			// 等待XDP程序加载
			waitForXDPOnDstWorkloads(t, dst)

			for _, tc := range authzCases {

				var additionalRule string

				// 总是允许健康检查端口，不受header策略影响
				if tc.name == "allow" {
					additionalRule = fmt.Sprintf(`
  - to:                                    # 规则1：总是允许健康检查端口（不受header限制）
    - operation:
        ports: ["%d", "%d", "%d"]`, readyPort, livenessPort, targetHttpPodPort)
				} else {
					additionalRule = fmt.Sprintf(`
  - to:                                    # 规则1：随意设置一个端口，避免所有tcp端口被拒绝
    - operation:
        ports: ["%d"]`, denyPort)
				}
				t.ConfigIstio().Eval(apps.Namespace.Name(), map[string]string{
					"Destination": dst.Config().Service,
					"TargetHost":  selectedHost, // app的第一个host值
				}, `apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: host-policy
spec:
  selector:
    matchLabels:
      app: "{{.Destination}}"
`+tc.spec+`
  rules:`+additionalRule+`
  - to:
    - operation:
        hosts: ["{{.TargetHost}}"]
`).ApplyOrFail(t)

				for _, hostTest := range hostTestCases {
					opt := echo.CallOptions{
						To:     dst,
						Port:   echo.Port{Name: "http", ServicePort: targetHttpServicePort}, // 使用HTTP端口进行Host测试
						Scheme: scheme.HTTP,                                                 // Host需要HTTP协议
						HTTP: echo.HTTP{
							Path: "/api/test",
							Headers: map[string][]string{
								"Host": {hostTest.hostValue}, // 修改HTTP请求的Host字段
							},
						},
						NewConnectionPerRequest: true,
						// Due to the mechanism of Kmesh L4 authorization, we need to set the timeout slightly longer.
						Timeout: time.Minute * 2,
					}

					var name string
					name = tc.name + ", " + hostTest.description

					opt.Check = chooseChecker(tc.name, hostTest.matches)

					t.NewSubTestf("%v", name).Run(func(t framework.TestContext) {
						src.WithWorkloads(client).CallOrFail(t, opt)
					})
				}

			}
		})
	})
}
