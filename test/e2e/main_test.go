//go:build integ
// +build integ

package kmesh

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"

	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/config/schema/gvk"
	istioKube "istio.io/istio/pkg/kube"
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
	"istio.io/istio/tests/integration/security/util/cert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gateway "sigs.k8s.io/gateway-api/apis/v1"
)

var (
	i istio.Instance

	// KmeshSrc is the location of Kmesh source.
	KmeshSrc = getDefaultKmeshSrc()

	KmeshNS = "kmesh-system"

	apps = &EchoDeployments{}
)

type EchoDeployments struct {
	// Namespace echo apps will be deployed
	Namespace namespace.Instance

	// AllWaypoint is a waypoint for all types
	AllWaypoint echo.Instances
	// WorkloadAddressedWaypoint is a workload only waypoint
	WorkloadAddressedWaypoint echo.Instances
	// ServiceAddressedWaypoint is a service only waypoint
	ServiceAddressedWaypoint echo.Instances
	// Captured echo service
	Captured echo.Instances
	// Uncaptured echo service
	Uncaptured echo.Instances

	// All echo services
	All echo.Instances

	// WaypointProxies by
	WaypointProxies map[string]ambient.WaypointProxy
}

const (
	WorkloadAddressedWaypoint = "workload-addressed-waypoint"
	ServiceAddressedWaypoint  = "service-addressed-waypoint"
	Captured                  = "captured"
	Uncaptured                = "uncaptured"
	WaypointImageAnnotation   = "sidecar.istio.io/proxyImage"
	KmeshCustomWaypointImage  = "ghcr.io/kmesh-net/waypoint-x86:v0.3.0"
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
		Setup(istio.Setup(&i, func(ctx resource.Context, cfg *istio.Config) {
			// can't deploy VMs without eastwest gateway
			ctx.Settings().SkipVMs()
			cfg.EnableCNI = true
			cfg.DeployEastWestGW = false
		}, cert.CreateCASecretAlt)).
		Setup(func(t resource.Context) error {
			scopes.Framework.Info("=== BEGIN: Deploy Kmesh ===")

			err := SetupKmesh(t)
			if err != nil {
				scopes.Framework.Info("=== FAILED: Deploy Kmesh ===")
				return err
			}

			scopes.Framework.Info("=== SUCCEEDED: Deploy Kmesh ===")

			return nil
		}).
		Setup(func(t resource.Context) error {
			return SetupApps(t, i, apps)
		}).
		Run()
}

func SetupKmesh(ctx resource.Context) error {
	yamls, err := getKmeshYamls()
	if err != nil {
		return err
	}

	return ctx.Clusters().Default().ApplyYAMLFiles("", yamls...)
}

func getKmeshYamls() ([]string, error) {
	KmeshInstallFilePath := path.Join(KmeshSrc, "deploy/yaml/")

	files, err := os.ReadDir(KmeshInstallFilePath)
	if err != nil {
		return nil, err
	}

	results := []string{}
	for _, file := range files {
		if file.IsDir() {
			// TODO: consider the situation of multiple directories in the future.
			continue
		}

		results = append(results, filepath.Join(KmeshInstallFilePath, file.Name()))
	}

	return results, nil
}

func SetupApps(t resource.Context, i istio.Instance, apps *EchoDeployments) error {
	var err error
	apps.Namespace, err = namespace.New(t, namespace.Config{
		Prefix: "echo",
		Inject: false,
		Labels: map[string]string{
			constants.DataplaneModeLabel: "ambient",
		},
	})
	if err != nil {
		return err
	}

	builder := deployment.New(t).
		WithClusters(t.Clusters()...).
		WithConfig(echo.Config{
			Service:               WorkloadAddressedWaypoint,
			Namespace:             apps.Namespace,
			Ports:                 ports.All(),
			ServiceAccount:        true,
			WorkloadWaypointProxy: "waypoint",
			Subsets: []echo.SubsetConfig{
				{
					Replicas: 1,
					Version:  "v1",
					Labels: map[string]string{
						"app":                             WorkloadAddressedWaypoint,
						"version":                         "v1",
						constants.AmbientUseWaypointLabel: "waypoint",
					},
				},
				{
					Replicas: 1,
					Version:  "v2",
					Labels: map[string]string{
						"app":                             WorkloadAddressedWaypoint,
						"version":                         "v2",
						constants.AmbientUseWaypointLabel: "waypoint",
					},
				},
			},
		}).
		WithConfig(echo.Config{
			Service:              ServiceAddressedWaypoint,
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
						"app":     ServiceAddressedWaypoint,
						"version": "v1",
					},
				},
				{
					Replicas: 1,
					Version:  "v2",
					Labels: map[string]string{
						"app":     ServiceAddressedWaypoint,
						"version": "v2",
					},
				},
			},
		}).
		WithConfig(echo.Config{
			Service:        Captured,
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
		}).
		WithConfig(echo.Config{
			Service:        Uncaptured,
			Namespace:      apps.Namespace,
			Ports:          ports.All(),
			ServiceAccount: true,
			Subsets: []echo.SubsetConfig{
				{
					Replicas: 1,
					Version:  "v1",
					Labels:   map[string]string{constants.DataplaneModeLabel: constants.DataplaneModeNone},
				},
				{
					Replicas: 1,
					Version:  "v2",
					Labels:   map[string]string{constants.DataplaneModeLabel: constants.DataplaneModeNone},
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
	apps.WorkloadAddressedWaypoint = match.ServiceName(echo.NamespacedName{Name: WorkloadAddressedWaypoint, Namespace: apps.Namespace}).GetMatches(echos)
	apps.ServiceAddressedWaypoint = match.ServiceName(echo.NamespacedName{Name: ServiceAddressedWaypoint, Namespace: apps.Namespace}).GetMatches(echos)
	apps.AllWaypoint = apps.AllWaypoint.Append(apps.WorkloadAddressedWaypoint)
	apps.AllWaypoint = apps.AllWaypoint.Append(apps.ServiceAddressedWaypoint)
	apps.Captured = match.ServiceName(echo.NamespacedName{Name: Captured, Namespace: apps.Namespace}).GetMatches(echos)
	apps.Uncaptured = match.ServiceName(echo.NamespacedName{Name: Uncaptured, Namespace: apps.Namespace}).GetMatches(echos)

	if apps.WaypointProxies == nil {
		apps.WaypointProxies = make(map[string]ambient.WaypointProxy)
	}

	for _, echo := range echos {
		svcwp := echo.Config().ServiceWaypointProxy
		wlwp := echo.Config().WorkloadWaypointProxy
		if svcwp != "" {
			if _, found := apps.WaypointProxies[svcwp]; !found {
				apps.WaypointProxies[svcwp], err = newWaypointProxy(t, apps.Namespace, svcwp)
				if err != nil {
					return err
				}
			}
		}
		if wlwp != "" {
			if _, found := apps.WaypointProxies[wlwp]; !found {
				apps.WaypointProxies[wlwp], err = newWaypointProxy(t, apps.Namespace, wlwp)
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

func newWaypointProxy(ctx resource.Context, ns namespace.Instance, name string) (ambient.WaypointProxy, error) {
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

	gw.Annotations[WaypointImageAnnotation] = KmeshCustomWaypointImage

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
