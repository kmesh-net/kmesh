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
	 lines := strings.Split(nslookup, "\n")
	 var addresses []string
	 for _, line := range lines {
		 trimmed := strings.TrimSpace(line)
		 if strings.HasPrefix(trimmed, "Address:") {
			 addr := strings.TrimSpace(strings.TrimPrefix(trimmed, "Address:"))
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
		 const fqdn = "helloworld." + ns + ".svc.cluster.local"
 
		 // Create the namespace.
		 shell.Execute(true, "kubectl create namespace "+ns)
 
		 // Apply the Service manifest.
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
 
		 // Deploy the local instance on the worker node.
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
			 t.Fatalf("Failed to deploy local instance: %v", err)
		 }
 
		 // Deploy the remote instance on the control-plane node.
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
			 t.Fatalf("Failed to deploy remote instance: %v", err)
		 }
 
		 // Deploy the sleep client on the worker node.
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
 
		 // Wait for deployments.
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
 
		 // Get the sleep pod name.
		 sleepPod, err := shell.Execute(true, "kubectl get pod -n "+ns+" -l app=sleep -o jsonpath='{.items[0].metadata.name}'")
		 if err != nil || sleepPod == "" {
			 t.Fatalf("Failed to get sleep pod: %v", err)
		 }
 
		 // Extract the resolved IP via nslookup.
		 nslookup, _ := shell.Execute(true, "kubectl exec -n "+ns+" "+sleepPod+" -- nslookup "+fqdn)
		 resolvedIP := extractResolvedIP(nslookup)
		 if resolvedIP == "" {
			 t.Fatalf("Failed to extract resolved IP from nslookup output")
		 }
 
		 // Test Locality Preference.
		 var localResponse string
		 if err := retry.Until(func() bool {
			 out, execErr := shell.Execute(true,
				 "kubectl exec -n "+ns+" "+sleepPod+" -- curl -v -sSL --resolve "+fqdn+":5000:"+resolvedIP+" http://"+fqdn+":5000/hello")
			 if execErr != nil {
				 return false
			 }
			 if strings.Contains(out, "region.zone1.subzone1") {
				 localResponse = out
				 return true
			 }
			 return false
		 }, retry.Timeout(60*time.Second), retry.Delay(2*time.Second)); err != nil {
			 t.Fatalf("Locality preferred test failed: expected response from region.zone1/subzone1, got: %s", localResponse)
		 }
 
		 // Test Locality Failover.
		 if _, err := shell.Execute(true, "kubectl delete deployment helloworld-region-zone1-subzone1 -n "+ns); err != nil {
			 t.Fatalf("Failed to delete local instance: %v", err)
		 }
		 var failoverResponse string
		 if err := retry.Until(func() bool {
			 out, execErr := shell.Execute(true,
				 "kubectl exec -n "+ns+" "+sleepPod+" -- curl -v -sSL --resolve "+fqdn+":5000:"+resolvedIP+" http://"+fqdn+":5000/hello")
			 if execErr != nil {
				 return false
			 }
			 if strings.Contains(out, "region.zone1.subzone2") {
				 failoverResponse = out
				 return true
			 }
			 return false
		 }, retry.Timeout(60*time.Second), retry.Delay(2*time.Second)); err != nil {
			 t.Fatalf("Locality failover test failed: expected response from region.zone1/subzone2, got: %s", failoverResponse)
		 }
	 })
 }
 