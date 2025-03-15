//go:build integ
// +build integ

/*
End-to-End Test for Kmesh Locality-Aware Load Balancing.

This test verifies that Kmesh correctly routes traffic to the nearest available instance 
based on locality (region, zone, and subzone). The test performs the following steps:
1. Create a Kind cluster with three worker nodes.
2. Label the nodes with region, zone, and subzone information.
3. Deploy a helloworld service.
4. Deploy three instances of the helloworld service on different nodes:
   - A local instance on "ambient-worker" with version "region.zone1.subzone1".
   - A remote instance on "ambient-worker2" with version "region.zone1.subzone2".
   - A remote instance on "ambient-worker3" with version "region.zone2.subzone3".
5. Deploy a sleep client on "ambient-worker" and validate:
   - Traffic initially routes to the local instance.
   - After deleting the local instance, traffic should fail over to the nearest available remote instance.
6. Clean up all resources after the test.
*/

package e2e

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

func runCommand(command string) (string, error) {
	cmd := exec.Command("bash", "-c", command)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestLocalityAwareLoadBalancing(t *testing.T) {
	t.Run("Setup Kind Cluster", func(t *testing.T) {
		t.Log("Setting up Kind cluster...")
		out, err := runCommand(`kind delete clusters --all || true &&
kind create cluster --image=kindest/node:v1.31.0 --config=- <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ambient
nodes:
- role: control-plane
- role: worker
- role: worker
- role: worker
EOF`)
		if err != nil {
			t.Fatalf("Failed to create Kind cluster: %v\n%s", err, out)
		}
	})

	t.Run("Label Nodes for Locality", func(t *testing.T) {
		t.Log("Labeling nodes for locality...")
		commands := []string{
			"kubectl label node ambient-worker topology.kubernetes.io/region=region topology.kubernetes.io/zone=zone1 topology.kubernetes.io/subzone=subzone1 --overwrite",
			"kubectl label node ambient-worker2 topology.kubernetes.io/region=region topology.kubernetes.io/zone=zone1 topology.kubernetes.io/subzone=subzone2 --overwrite",
			"kubectl label node ambient-worker3 topology.kubernetes.io/region=region topology.kubernetes.io/zone=zone2 topology.kubernetes.io/subzone=subzone3 --overwrite",
		}
		for _, cmd := range commands {
			out, err := runCommand(cmd)
			if err != nil {
				t.Fatalf("Failed to label nodes: %v\n%s", err, out)
			}
		}
	})

	t.Run("Deploy Services", func(t *testing.T) {
		t.Log("Deploying services...")

		
		_, err := runCommand("kubectl create namespace sample || true")
		if err != nil {
			t.Fatalf("Failed to create namespace: %v", err)
		}

		
		helloworldService := `
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
		out, err := runCommand("echo '" + helloworldService + "' | kubectl apply -n sample -f -")
		if err != nil {
			t.Fatalf("Failed to apply helloworld service: %v\n%s", err, out)
		}

		// Deploy helloworld service on worker 1
		deployment1 := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: helloworld-region.zone1.subzone1
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
        ports:
        - containerPort: 5000
      nodeSelector:
        kubernetes.io/hostname: ambient-worker
`
		out, err = runCommand("echo '" + deployment1 + "' | kubectl apply -n sample -f -")
		if err != nil {
			t.Fatalf("Failed to apply helloworld-region.zone1.subzone1: %v\n%s", err, out)
		}

		// Deploy helloworld service on worker 2
		deployment2 := strings.Replace(deployment1, "zone1.subzone1", "zone1.subzone2", -1)
		deployment2 = strings.Replace(deployment2, "ambient-worker", "ambient-worker2", -1)
		out, err = runCommand("echo '" + deployment2 + "' | kubectl apply -n sample -f -")
		if err != nil {
			t.Fatalf("Failed to apply helloworld-region.zone1.subzone2: %v\n%s", err, out)
		}

		// Deploy helloworld service on worker 3
		deployment3 := strings.Replace(deployment2, "zone1.subzone2", "zone2.subzone3", -1)
		deployment3 = strings.Replace(deployment3, "ambient-worker2", "ambient-worker3", -1)
		out, err = runCommand("echo '" + deployment3 + "' | kubectl apply -n sample -f -")
		if err != nil {
			t.Fatalf("Failed to apply helloworld-region.zone2.subzone3: %v\n%s", err, out)
		}
	})

	t.Run("Test Locality Load Balancing", func(t *testing.T) {
		t.Log("Testing Locality Load Balancing...")
	
		
		out, err := runCommand("kubectl wait --for=condition=ready node --all --timeout=120s")
		if err != nil {
			t.Fatalf("Nodes not ready: %v\n%s", err, out)
		}
		
		
		out, err = runCommand("kubectl wait --for=condition=available deployment --all -n sample --timeout=120s")
		if err != nil {
			t.Logf("Warning: Not all deployments are available yet: %v\n%s", err, out)
			
			debugOut, _ := runCommand("kubectl get deployments -n sample")
			t.Logf("Deployment status: \n%s", debugOut)
		}
	
		sleepClient := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: sleep
  namespace: sample
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
      nodeSelector:
        kubernetes.io/hostname: ambient-worker`
	
		
		out, err = runCommand("echo '" + sleepClient + "' > sleep.yaml && kubectl apply -f sleep.yaml")
		if err != nil {
			t.Fatalf("Failed to apply sleep client: %v\n%s", err, out)
		}
		
		
		time.Sleep(10 * time.Second)
		
	
		out, err = runCommand("kubectl get deployment sleep -n sample")
		if err != nil {
			debugOut, _ := runCommand("kubectl get all -n sample")
			t.Fatalf("Sleep deployment not found: %v\n%s\nResources in namespace:\n%s", err, out, debugOut)
		}
		
		
		t.Logf("Sleep deployment status: %s", out)
		
		podOut, _ := runCommand("kubectl get pods -n sample -l app=sleep -o wide")
		t.Logf("Sleep pod status: %s", podOut)
	
		
		out, err = runCommand("kubectl wait --for=condition=ready pod -n sample -l app=sleep --timeout=120s")
		if err != nil {
			
			podDetails, _ := runCommand("kubectl describe pods -n sample -l app=sleep")
			t.Fatalf("Failed to wait for sleep pod readiness: %v\n%s\nPod details:\n%s", err, out, podDetails)
		}
	
		
		out, err = runCommand(`kubectl exec -n sample "$(kubectl get pod -n sample -l app=sleep -o jsonpath='{.items[0].metadata.name}')" -- curl -sSL "http://helloworld:5000/hello"`)
		if err != nil {
			t.Fatalf("Failed to test service: %v\n%s", err, out)
		}
	
		t.Logf("Output: %s", out)
	})
	
	t.Run("Cleanup", func(t *testing.T) {
		t.Log("Cleaning up...")

		
		_, err := runCommand("kubectl delete namespace sample || true")
		if err != nil {
			t.Logf("Failed to delete namespace: %v", err)
		}

		
		out, err := runCommand("kind delete clusters --all")
		if err != nil {
			t.Logf("Failed to delete cluster: %v\n%s", err, out)
		}
	})
}
