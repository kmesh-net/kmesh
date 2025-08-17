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

// Wait for all the XDP programs of dst to load
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

			// Define the test port
			selectedPodPort := 19090
			selectedServicePort := 9090
			notSelectedPodPort := 16060
			notSelectedServicePort := 9091

			// Echo Pod healthy port
			readyPort := 8080
			livenessPort := 3333

			authzCases := []struct {
				name  string
				spec  string
				ports string
			}{
				{
					name:  "allow",
					spec:  `  action: ALLOW`,
					ports: fmt.Sprintf(`["%d", "%d", "%d"]`, selectedPodPort, readyPort, livenessPort),
				},
				{
					name:  "deny",
					spec:  `  action: DENY`,
					ports: fmt.Sprintf(`["%d"]`, selectedPodPort),
				},
			}

			chooseChecker := func(action string, servicePort int) echo.Checker {
				switch action {
				case "allow":
					if servicePort == selectedServicePort {
						return check.OK()
					} else {
						return check.NotOK()
					}
				case "deny":
					if servicePort == selectedServicePort {
						return check.NotOK()
					} else {
						return check.OK()
					}
				default:
					t.Fatal("invalid action")
				}

				return check.OK()
			}

			portTestCases := []struct {
				servicePort int
				podPort     int
				description string
			}{
				{
					servicePort: selectedServicePort,
					podPort:     selectedPodPort,
					description: fmt.Sprintf("service port %d (pod port %d)", selectedServicePort, selectedPodPort),
				},
				{
					servicePort: notSelectedServicePort,
					podPort:     notSelectedPodPort,
					description: fmt.Sprintf("service port %d (pod port %d)", notSelectedServicePort, notSelectedPodPort),
				},
			}

			waitForXDPOnDstWorkloads(t, dst)

			for _, tc := range authzCases {
				t.ConfigIstio().Eval(apps.Namespace.Name(), map[string]string{
					"Destination": dst.Config().Service,
					"Ports":       tc.ports,
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
						Port:                    echo.Port{Name: "tcp", ServicePort: portTest.servicePort},
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

			// get the namespace of the apps
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

			waitForXDPOnDstWorkloads(t, dst)

			for _, tc := range authzCases {
				t.ConfigIstio().Eval(apps.Namespace.Name(), map[string]string{
					"Destination":     dst.Config().Service,
					"SourceNamespace": selectedNamespace,
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