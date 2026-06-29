package utils

import (
    "context"
    "errors"
    "os"
    "path/filepath"
    "strings"
    "testing"

    v1 "k8s.io/api/core/v1"
    "k8s.io/client-go/kubernetes"
    gatewayapiclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

    "kmesh.net/kmesh/pkg/kube"
)

type fakePortForwarder struct{}

func (f *fakePortForwarder) Start() error   { return nil }
func (f *fakePortForwarder) Address() string { return "127.0.0.1:1234" }
func (f *fakePortForwarder) Close()         {}

type fakeCLIClient struct {
    gotPodName      string
    gotNamespace    string
    gotLocalAddress string
    gotLocalPort    int
    gotPodPort      int
    pf              kube.PortForwarder
    err             error
}

func (f *fakeCLIClient) Kube() kubernetes.Interface { return nil }
func (f *fakeCLIClient) GatewayAPI() gatewayapiclient.Interface { return nil }
func (f *fakeCLIClient) PodsForSelector(ctx context.Context, namespace string, labelSelectors ...string) (*v1.PodList, error) {
    return &v1.PodList{}, nil
}
func (f *fakeCLIClient) NewPortForwarder(podName, ns, localAddress string, localPort, podPort int) (kube.PortForwarder, error) {
    f.gotPodName = podName
    f.gotNamespace = ns
    f.gotLocalAddress = localAddress
    f.gotLocalPort = localPort
    f.gotPodPort = podPort
    return f.pf, f.err
}

func writeTempKubeconfig(t *testing.T, content string) string {
    t.Helper()
    dir := t.TempDir()
    path := filepath.Join(dir, "config")
    if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
        t.Fatalf("write kubeconfig: %v", err)
    }
    return path
}

func TestCreateKubeClient_Success(t *testing.T) {
    cfg := `
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
    insecure-skip-tls-verify: true
  name: test
contexts:
- context:
    cluster: test
    user: test
  name: test
current-context: test
users:
- name: test
  user:
    token: dummy
`
    t.Setenv("KUBECONFIG", writeTempKubeconfig(t, cfg))

    cli, err := CreateKubeClient()
    if err != nil {
        t.Fatalf("CreateKubeClient() error = %v", err)
    }
    if cli == nil {
        t.Fatalf("CreateKubeClient() returned nil client")
    }
}

func TestCreateKubeClient_InvalidConfig(t *testing.T) {
    t.Setenv("KUBECONFIG", writeTempKubeconfig(t, "not: [valid"))

    cli, err := CreateKubeClient()
    if err == nil {
        t.Fatalf("CreateKubeClient() expected error, got nil")
    }
    if cli != nil {
        t.Fatalf("CreateKubeClient() expected nil client on error")
    }
}

func TestCreateKmeshPortForwarder_Success(t *testing.T) {
    fake := &fakeCLIClient{pf: &fakePortForwarder{}}

    fw, err := CreateKmeshPortForwarder(fake, "pod-1")
    if err != nil {
        t.Fatalf("CreateKmeshPortForwarder() error = %v", err)
    }
    if fw != fake.pf {
        t.Fatalf("CreateKmeshPortForwarder() returned unexpected forwarder")
    }
    if fake.gotNamespace != KmeshNamespace {
        t.Fatalf("namespace = %q, want %q", fake.gotNamespace, KmeshNamespace)
    }
    if fake.gotLocalAddress != "" {
        t.Fatalf("localAddress = %q, want empty", fake.gotLocalAddress)
    }
    if fake.gotLocalPort != 0 {
        t.Fatalf("localPort = %d, want 0", fake.gotLocalPort)
    }
    if fake.gotPodPort != KmeshAdminPort {
        t.Fatalf("podPort = %d, want %d", fake.gotPodPort, KmeshAdminPort)
    }
}

func TestCreateKmeshPortForwarder_Error(t *testing.T) {
    fake := &fakeCLIClient{err: errors.New("boom")}

    fw, err := CreateKmeshPortForwarder(fake, "pod-1")
    if err == nil || !strings.Contains(err.Error(), "failed to create port forwarder") {
        t.Fatalf("expected wrapped error, got %v", err)
    }
    if fw != nil {
        t.Fatalf("expected nil forwarder on error")
    }
}