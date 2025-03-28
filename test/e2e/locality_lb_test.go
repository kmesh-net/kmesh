// +build integ

package kmesh

import (
	"os"
	"strings"
	"testing"
	"time"

	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/shell"
	"istio.io/istio/pkg/test/util/retry"
)

// applyManifest writes the provided manifest into a temporary file and applies it using kubectl.
func applyManifest(ns, manifest string) error {
	tmpFile, err := os.CreateTemp("", "manifest-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(manifest); err != nil {
		tmpFile.Close()
		return err
	}
	tmpFile.Close()

	cmd := "kubectl apply -n " + ns + " -f " + tmpFile.Name()
	_, err = shell.Execute(true, cmd)
	return err
}

// extractResolvedIP parses the nslookup output to extract the IP address for the service.
func extractResolvedIP(nslookup string) string {
	// nslookup output typically contains two "Address:" lines.
	// The first is the DNS server; the second is the resolved IP.
	lines := strings.Split(nslookup, "\n")
	var addresses []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Address:") {
			// Remove the "Address:" prefix and trim again.
			addr := strings.TrimSpace(strings.TrimPrefix(trimmed, "Address:"))
			// If the address is enclosed in brackets (e.g. "[fd00:10:96::a]:53"), skip it.
			if strings.Contains(addr, ":53") || strings.HasPrefix(addr, "[") {
				continue
			}
			addresses = append(addresses, addr)
		}
	}
	if len(addresses) > 0 {
		return addresses[0]
	}
	return ""
}

func TestLocalityLoadBalancing(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		const ns = "sample"
		// Fully qualified domain name for the service.
		const fqdn = "helloworld." + ns + ".svc.cluster.local"

		// Create the test namespace.
		if _, err := shell.Execute(true, "kubectl create namespace "+ns); err != nil {
			t.Logf("Namespace %s might already exist: %v", ns, err)
		}

		// Debug: List current pods and endpoints.
		pods, _ := shell.Execute(true, "kubectl get pods -n "+ns)
		t.Logf("Initial pods in namespace %s:\n%s", ns, pods)
		endpoints, _ := shell.Execute(true, "kubectl get endpoints helloworld -n "+ns)
		t.Logf("Initial endpoints for helloworld service:\n%s", endpoints)

		// Apply the Service manifest with PreferClose locality load balancing.
		serviceYAML := `
apiVersion: v1
kind: Service
metadata:
  name: helloworld
  labels:
    app: helloworld
spec:
  ports:
  - port: 5000
    name: http
  selector:
    app: helloworld
  trafficDistribution: PreferClose
`
		if err := applyManifest(ns, serviceYAML); err != nil {
			t.Fatalf("Failed to apply Service manifest: %v", err)
		}

		// Deploy the local instance (dep1) on the worker node.
		depLocal := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: helloworld-region-zone1-subzone1
  labels:
    app: helloworld
    version: region.zone1.subzone1
spec:
  replicas: 1
  selector:
    matchLabels:
      app: helloworld
      version: region.zone1.subzone1
  template:
    metadata:
      labels:
        app: helloworld
        version: region.zone1.subzone1
    spec:
      containers:
      - name: helloworld
        env:
        - name: SERVICE_VERSION
          value: region.zone1.subzone1
        image: docker.io/istio/examples-helloworld-v1
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: 5000
      nodeSelector:
        kubernetes.io/hostname: kmesh-testing-worker
`
		if err := applyManifest(ns, depLocal); err != nil {
			t.Fatalf("Failed to deploy local instance (dep1): %v", err)
		}

		// Deploy the remote instance (dep2) on the control-plane node.
		depRemote := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: helloworld-region-zone1-subzone2
  labels:
    app: helloworld
    version: region.zone1.subzone2
spec:
  replicas: 1
  selector:
    matchLabels:
      app: helloworld
      version: region.zone1.subzone2
  template:
    metadata:
      labels:
        app: helloworld
        version: region.zone1.subzone2
    spec:
      containers:
      - name: helloworld
        env:
        - name: SERVICE_VERSION
          value: region.zone1.subzone2
        image: docker.io/istio/examples-helloworld-v1
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: 5000
      nodeSelector:
        kubernetes.io/hostname: kmesh-testing-control-plane
      tolerations:
      - key: "node-role.kubernetes.io/control-plane"
        operator: "Exists"
        effect: "NoSchedule"
`
		if err := applyManifest(ns, depRemote); err != nil {
			t.Fatalf("Failed to deploy remote instance (dep2): %v", err)
		}

		// Deploy a sleep client on the worker node.
		clientDep := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sleep
  labels:
    app: sleep
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sleep
  template:
    metadata:
      labels:
        app: sleep
    spec:
      containers:
      - name: sleep
        image: curlimages/curl
        command: ["/bin/sleep", "infinity"]
        imagePullPolicy: IfNotPresent
      nodeSelector:
        kubernetes.io/hostname: kmesh-testing-worker
`
		if err := applyManifest(ns, clientDep); err != nil {
			t.Fatalf("Failed to deploy sleep client: %v", err)
		}

		// Wait for all deployments to be available.
		deployments := []string{
			"helloworld-region-zone1-subzone1",
			"helloworld-region-zone1-subzone2",
			"sleep",
		}
		for _, dep := range deployments {
			cmd := "kubectl wait --for=condition=available deployment/" + dep + " -n " + ns + " --timeout=120s"
			if _, err := shell.Execute(true, cmd); err != nil {
				t.Fatalf("Deployment %s not ready: %v", dep, err)
			}
		}

		// Debug: List pods and endpoints after deployments.
		pods, _ = shell.Execute(true, "kubectl get pods -n "+ns)
		t.Logf("Pods after deployment in namespace %s:\n%s", ns, pods)
		endpoints, _ = shell.Execute(true, "kubectl get endpoints helloworld -n "+ns)
		t.Logf("Endpoints for service helloworld after deployment:\n%s", endpoints)

		// Debug: Check DNS resolution from the sleep pod.
		sleepPod, err := shell.Execute(true, "kubectl get pod -n "+ns+" -l app=sleep -o jsonpath='{.items[0].metadata.name}'")
		if err != nil || sleepPod == "" {
			t.Fatalf("Failed to get sleep pod: %v", err)
		}
		nslookup, _ := shell.Execute(true, "kubectl exec -n "+ns+" "+sleepPod+" -- nslookup "+fqdn)
		t.Logf("nslookup output for %s:\n%s", fqdn, nslookup)
		resolvedIP := extractResolvedIP(nslookup)
		if resolvedIP == "" {
			t.Fatalf("Failed to extract resolved IP from nslookup output")
		}
		t.Logf("Extracted resolved IP: %s", resolvedIP)

		// Test Locality Preference (PreferClose):
		t.Log("Testing locality preferred (expect response from region.zone1/subzone1)...")
		var localResponse string
		if err := retry.Until(func() bool {
			t.Logf("Attempting curl request at %s...", time.Now().Format(time.RFC3339))
			// Use --resolve to force curl to use the extracted IP.
			out, execErr := shell.Execute(true,
				"kubectl exec -n "+ns+" "+sleepPod+" -- curl -v -sSL --resolve "+fqdn+":5000:"+resolvedIP+" http://"+fqdn+":5000/hello")
			if execErr != nil {
				t.Logf("Curl error: %v", execErr)
				return false
			}
			t.Logf("Curl output: %s", out)
			if strings.Contains(out, "region.zone1.subzone1") {
				localResponse = out
				return true
			}
			return false
		}, retry.Timeout(60*time.Second), retry.Delay(2*time.Second)); err != nil {
			t.Fatalf("Locality preferred test failed: expected response from region.zone1/subzone1, got: %s", localResponse)
		}
		t.Log("Locality preferred test passed.")

		// Test Locality Failover:
		t.Log("Testing locality failover (expect response from region.zone1/subzone2)...")
		if _, err := shell.Execute(true, "kubectl delete deployment helloworld-region-zone1-subzone1 -n "+ns); err != nil {
			t.Fatalf("Failed to delete local instance (dep1): %v", err)
		}
		var failoverResponse string
		if err := retry.Until(func() bool {
			t.Logf("Attempting curl (failover) at %s...", time.Now().Format(time.RFC3339))
			out, execErr := shell.Execute(true,
				"kubectl exec -n "+ns+" "+sleepPod+" -- curl -v -sSL --resolve "+fqdn+":5000:"+resolvedIP+" http://"+fqdn+":5000/hello")
			if execErr != nil {
				t.Logf("Curl error after failover: %v", execErr)
				return false
			}
			t.Logf("Curl output after failover: %s", out)
			if strings.Contains(out, "region.zone1.subzone2") {
				failoverResponse = out
				return true
			}
			return false
		}, retry.Timeout(60*time.Second), retry.Delay(2*time.Second)); err != nil {
			t.Fatalf("Locality failover test failed: expected response from region.zone1/subzone2, got: %s", failoverResponse)
		}
		t.Log("Locality failover test passed.")
	})
}
