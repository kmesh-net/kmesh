//go:build integ
// +build integ

/*
 * Copyright 2024 The Kmesh Authors.
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
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/config/schema/gvk"
	istioKube "istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/ambient"
	"istio.io/istio/pkg/test/framework/components/crd"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/common/ports"
	"istio.io/istio/pkg/test/framework/components/echo/deployment"
	"istio.io/istio/pkg/test/framework/components/echo/match"
	"istio.io/istio/pkg/test/framework/components/istio"
	"istio.io/istio/pkg/test/framework/components/namespace"
	"istio.io/istio/pkg/test/framework/resource"
	testKube "istio.io/istio/pkg/test/kube"
	"istio.io/istio/pkg/test/scopes"
	"istio.io/istio/pkg/test/util/retry"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gateway "sigs.k8s.io/gateway-api/apis/v1"
)

var (
	i istio.Instance

	// KmeshSrc is the location of Kmesh source.
	KmeshSrc = getDefaultKmeshSrc()

	apps = &EchoDeployments{}
)

type EchoDeployments struct {
	// Namespace echo apps will be deployed
	Namespace namespace.Instance

	// All echo services
	All echo.Instances

	// The echo service which is enrolled to Kmesh without waypoint.
	EnrolledToKmesh echo.Instances

	// The echo service which is enrolled to Kmesh and with service waypoint.
	ServiceWithWaypointAtServiceGranularity echo.Instances

	// WaypointProxies by
	WaypointProxies map[string]ambient.WaypointProxy
}

const (
	ServiceWithWaypointAtServiceGranularity = "service-with-waypoint-at-service-granularity"
	EnrolledToKmesh                         = "enrolled-to-kmesh"
	WaypointImageAnnotation                 = "sidecar.istio.io/proxyImage"
	Timeout                                 = 2 * time.Minute
	KmeshReleaseName                        = "kmesh"
	KmeshDaemonsetName                      = "kmesh"
	KmeshNamespace                          = "kmesh-system"
)

func getDefaultKmeshSrc() string {
	_, b, _, _ := runtime.Caller(0)

	// Root folder of the project.
	// This relies on the fact that this file is 2 levels up from the root; if this changes, adjust the path below.
	return filepath.Join(filepath.Dir(b), "../..")
}

func TestMain(m *testing.M) {
	// nolint: staticcheck
	framework.
		NewSuite(m).
		Setup(func(t resource.Context) error {
			t.Settings().Ambient = true
			return nil
		}).
		Setup(func(t resource.Context) error {
			return SetupApps(t, i, apps)
		}).
		Run()
}

func SetupApps(t resource.Context, i istio.Instance, apps *EchoDeployments) error {
	var err error
	apps.Namespace, err = namespace.New(t, namespace.Config{
		Prefix: "echo",
		Inject: false,
		Labels: map[string]string{
			constants.DataplaneModeLabel: "Kmesh",
		},
	})
	if err != nil {
		return err
	}

	builder := deployment.New(t).
		WithClusters(t.Clusters()...).
		WithConfig(echo.Config{
			Service:              ServiceWithWaypointAtServiceGranularity,
			Namespace:            apps.Namespace,
			Ports:                ports.All(),
			ServiceLabels:        map[string]string{constants.AmbientUseWaypointLabel: "waypoint"},
			ServiceAccount:       true,
			ServiceWaypointProxy: "waypoint",
			Subsets: []echo.SubsetConfig{
				{
					Replicas: 1,
					Version:  "v1",
					Labels: map[string]string{
						"app":     ServiceWithWaypointAtServiceGranularity,
						"version": "v1",
					},
				},
				{
					Replicas: 1,
					Version:  "v2",
					Labels: map[string]string{
						"app":     ServiceWithWaypointAtServiceGranularity,
						"version": "v2",
					},
				},
			},
		}).
		WithConfig(echo.Config{
			Service:        EnrolledToKmesh,
			Namespace:      apps.Namespace,
			Ports:          ports.All(),
			ServiceAccount: true,
			Subsets: []echo.SubsetConfig{
				{
					Replicas: 1,
					Version:  "v1",
				},
				{
					Replicas: 1,
					Version:  "v2",
				},
			},
		})

	echos, err := builder.Build()
	if err != nil {
		return err
	}
	for _, b := range echos {
		scopes.Framework.Infof("built %v", b.Config().Service)
	}
	apps.All = echos
	apps.EnrolledToKmesh = match.ServiceName(echo.NamespacedName{Name: EnrolledToKmesh, Namespace: apps.Namespace}).GetMatches(echos)
	apps.ServiceWithWaypointAtServiceGranularity = match.ServiceName(echo.NamespacedName{Name: ServiceWithWaypointAtServiceGranularity, Namespace: apps.Namespace}).GetMatches(echos)

	if apps.WaypointProxies == nil {
		apps.WaypointProxies = make(map[string]ambient.WaypointProxy)
	}

	for _, echo := range echos {
		svcwp := echo.Config().ServiceWaypointProxy
		wlwp := echo.Config().WorkloadWaypointProxy
		if svcwp != "" {
			if _, found := apps.WaypointProxies[svcwp]; !found {
				apps.WaypointProxies[svcwp], err = newWaypointProxy(t, apps.Namespace, svcwp, constants.ServiceTraffic)
				if err != nil {
					return err
				}
			}
		}
		if wlwp != "" {
			if _, found := apps.WaypointProxies[wlwp]; !found {
				apps.WaypointProxies[wlwp], err = newWaypointProxy(t, apps.Namespace, wlwp, constants.WorkloadTraffic)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

var _ io.Closer = &kubeComponent{}

type kubeComponent struct {
	id resource.ID

	ns       namespace.Instance
	inbound  istioKube.PortForwarder
	outbound istioKube.PortForwarder
	pod      v1.Pod
}

func (k kubeComponent) Namespace() namespace.Instance {
	return k.ns
}

func (k kubeComponent) PodIP() string {
	return k.pod.Status.PodIP
}

func (k kubeComponent) Inbound() string {
	return k.inbound.Address()
}

func (k kubeComponent) Outbound() string {
	return k.outbound.Address()
}

func (k kubeComponent) ID() resource.ID {
	return k.id
}

func (k kubeComponent) Close() error {
	if k.inbound != nil {
		k.inbound.Close()
	}
	if k.outbound != nil {
		k.outbound.Close()
	}
	return nil
}

func newWaypointProxyOrFail(t test.Failer, ctx resource.Context, ns namespace.Instance, name string, trafficType string) {
	if _, err := newWaypointProxy(ctx, ns, name, trafficType); err != nil {
		t.Fatal("create new waypoint proxy failed: %v", err)
	}
}

func newWaypointProxy(ctx resource.Context, ns namespace.Instance, name string, trafficType string) (ambient.WaypointProxy, error) {
	err := crd.DeployGatewayAPI(ctx)
	if err != nil {
		return nil, err
	}

	gw := &gateway.Gateway{
		TypeMeta: metav1.TypeMeta{
			Kind:       gvk.KubernetesGateway_v1.Kind,
			APIVersion: gvk.KubernetesGateway_v1.GroupVersion(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   ns.Name(),
			Annotations: make(map[string]string, 0),
			Labels: map[string]string{
				constants.AmbientWaypointForTrafficTypeLabel: trafficType,
			},
		},
		Spec: gateway.GatewaySpec{
			GatewayClassName: constants.WaypointGatewayClassName,
			Listeners: []gateway.Listener{{
				Name:     "mesh",
				Port:     15008,
				Protocol: gateway.ProtocolType(protocol.HBONE),
			}},
		},
	}

	waypointImage := os.Getenv("KMESH_WAYPOINT_IMAGE")
	if waypointImage == "" {
		return nil, fmt.Errorf("failed to get Kmesh custom waypoint image from env")
	}

	gw.Annotations[WaypointImageAnnotation] = waypointImage

	cls := ctx.Clusters().Default()

	gwc := cls.GatewayAPI().GatewayV1().Gateways(ns.Name())

	_, err = gwc.Create(context.Background(), gw, metav1.CreateOptions{
		FieldManager: "istioctl",
	})
	if err != nil {
		return nil, err
	}

	fetchFn := testKube.NewSinglePodFetch(cls, ns.Name(), fmt.Sprintf("%s=%s", constants.GatewayNameLabel, name))
	pods, err := testKube.WaitUntilPodsAreReady(fetchFn)
	if err != nil {
		return nil, err
	}
	pod := pods[0]
	inbound, err := cls.NewPortForwarder(pod.Name, pod.Namespace, "", 0, 15008)
	if err != nil {
		return nil, err
	}

	outbound, err := cls.NewPortForwarder(pod.Name, pod.Namespace, "", 0, 15001)
	if err != nil {
		return nil, err
	}

	if err := outbound.Start(); err != nil {
		return nil, err
	}

	server := &kubeComponent{
		ns: ns,
	}
	server.id = ctx.TrackResource(server)
	server.inbound = inbound
	server.outbound = outbound
	server.pod = pod

	return server, nil
}

func deleteWaypointProxyOrFail(t test.Failer, ctx resource.Context, ns namespace.Instance, name string) {
	if err := deleteWaypointProxy(ctx, ns, name); err != nil {
		t.Fatal("delete waypoint proxy failed: %v", err)
	}
}

func deleteWaypointProxy(ctx resource.Context, ns namespace.Instance, name string) error {
	cls := ctx.Clusters().Default()

	if err := cls.GatewayAPI().GatewayV1().Gateways(ns.Name()).Delete(context.Background(), name, metav1.DeleteOptions{}); err != nil {
		return err
	}

	// Make sure the pods associated with the waypoint have been deleted to prevent affecting other test cases.
	return retry.UntilSuccess(func() error {
		pods, err := cls.Kube().CoreV1().Pods(ns.Name()).List(context.TODO(), metav1.ListOptions{
			LabelSelector: fmt.Sprintf("%s=%s", constants.GatewayNameLabel, name),
		})
		if err != nil {
			return err
		}
		if len(pods.Items) != 0 {
			return fmt.Errorf("pods have not been completely deleted")
		}

		return nil
	}, retry.Timeout(time.Minute*10), retry.BackoffDelay(time.Millisecond*200))
}
