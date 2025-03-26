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
	 // Ensure the temporary file is removed after use.
	 defer os.Remove(tmpFile.Name())
 
	 // Write the manifest to the temporary file.
	 if _, err := tmpFile.WriteString(manifest); err != nil {
		 tmpFile.Close()
		 return err
	 }
	 tmpFile.Close()
 
	 cmd := "kubectl apply -n " + ns + " -f " + tmpFile.Name()
	 _, err = shell.Execute(true, cmd)
	 return err
 }
 
 func TestLocalityLoadBalancing(t *testing.T) {
	 framework.NewTest(t).Run(func(t framework.TestContext) {
		 const ns = "sample"
 
		 // Create the test namespace "sample". Log but ignore errors if it already exists.
		 if _, err := shell.Execute(true, "kubectl create namespace "+ns); err != nil {
			 t.Logf("Namespace %s might already exist: %v", ns, err)
		 }
 
		 // Apply the Service manifest with PreferClose load balancing.
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
		 // This instance simulates the "local" deployment.
		 dep1 := `
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
		 if err := applyManifest(ns, dep1); err != nil {
			 t.Fatalf("Failed to deploy local instance (dep1): %v", err)
		 }
 
		 // Deploy the remote instance (dep2) on the control-plane node.
		 // Note: A toleration is added here so that the pod can be scheduled on the control-plane.
		 dep2 := `
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
		 if err := applyManifest(ns, dep2); err != nil {
			 t.Fatalf("Failed to deploy remote instance (dep2): %v", err)
		 }
 
		 // Deploy a sleep client on the worker node.
		 // This client will originate requests from the "local" node.
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
 
		 // Wait for all deployments to become available.
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
 
		 // Test Locality Preferred:
		 // From the sleep client, access the helloworld service and expect a response from the local instance.
		 t.Log("Testing locality preferred (expect response from region.zone1.subzone1)...")
		 var localResponse string
		 if err := retry.Until(func() bool {
			 out, execErr := shell.Execute(true,
				 "kubectl exec -n "+ns+" $(kubectl get pod -n "+ns+" -l app=sleep -o jsonpath='{.items[0].metadata.name}') -c sleep -- curl -sSL http://helloworld:5000/hello")
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
			 t.Fatalf("Locality preferred test failed: expected response from region.zone1.subzone1, got: %s", localResponse)
		 }
		 t.Log("Locality preferred test passed.")
 
		 // Test Locality Failover:
		 // Delete the local deployment and expect traffic to fail over to the remote instance.
		 t.Log("Testing locality failover (expect response from region.zone1.subzone2)...")
		 if _, err := shell.Execute(true, "kubectl delete deployment helloworld-region-zone1-subzone1 -n "+ns); err != nil {
			 t.Fatalf("Failed to delete local instance (dep1): %v", err)
		 }
		 var failoverResponse string
		 if err := retry.Until(func() bool {
			 out, execErr := shell.Execute(true,
				 "kubectl exec -n "+ns+" $(kubectl get pod -n "+ns+" -l app=sleep -o jsonpath='{.items[0].metadata.name}') -c sleep -- curl -sSL http://helloworld:5000/hello")
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
			 t.Fatalf("Locality failover test failed: expected response from region.zone1.subzone2, got: %s", failoverResponse)
		 }
		 t.Log("Locality failover test passed.")
	 })
 }
 