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
	"time"

	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/config/schema/gvk"
	istioKube "istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/ambient"
	kubecluster "istio.io/istio/pkg/test/framework/components/cluster/kube"
	"istio.io/istio/pkg/test/framework/components/crd"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/common/ports"
	"istio.io/istio/pkg/test/framework/components/echo/deployment"
	"istio.io/istio/pkg/test/framework/components/istio"
	"istio.io/istio/pkg/test/framework/components/namespace"
	"istio.io/istio/pkg/test/framework/resource"
	"istio.io/istio/pkg/test/helm"
	testKube "istio.io/istio/pkg/test/kube"
	"istio.io/istio/pkg/test/scopes"
	"istio.io/istio/tests/integration/security/util/cert"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
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

	// WaypointProxies by
	WaypointProxies map[string]ambient.WaypointProxy
}

const (
	ServiceAddressedWaypoint = "service-addressed-waypoint"
	Enrolled                 = "enrolled"
	WaypointImageAnnotation  = "sidecar.istio.io/proxyImage"
	Timeout                  = 2 * time.Minute
	KmeshReleaseName         = "kmesh"
	KmeshNamespace           = "kmesh-system"
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
	cs := ctx.Clusters().Default().(*kubecluster.Cluster)

	if _, err := cs.Kube().CoreV1().Namespaces().Create(context.TODO(), &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: KmeshNamespace,
		},
	}, metav1.CreateOptions{}); err != nil {
		if !kerrors.IsAlreadyExists(err) {
			return fmt.Errorf("failed to create %v namespace: %v", KmeshNamespace, err)
		}
	}

	h := helm.New(cs.Filename())

	kmeshChartPath := path.Join(KmeshSrc, "deploy/helm/")

	// Install Kmesh chart
	err := h.InstallChartWithValues(KmeshReleaseName, kmeshChartPath, KmeshNamespace, []string{"--set deploy.kmesh.image.repository=localhost:5000/kmesh"}, Timeout)
	if err != nil {
		return fmt.Errorf("failed to install Kmesh chart: %v", err)
	}

	return nil
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
			Service:        Enrolled,
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
