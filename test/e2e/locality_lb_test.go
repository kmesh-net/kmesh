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
   "fmt"
   "os"
   "path/filepath"
   "strings"
   "testing"
   "time"
 
   "istio.io/istio/pkg/test/framework"
   "istio.io/istio/pkg/test/shell"
   "istio.io/istio/pkg/test/util/retry"
 )
 
 func runCommand(ctx framework.TestContext, cmd string) string {
   out, err := shell.Execute(true, cmd)
   if err != nil {
     ctx.Fatalf("Command %q failed: %v\n%s", cmd, err, out)
   }
   ctx.Logf(">>> Command succeeded: %s\n%s", cmd, out)
   return out
 }

 func applyManifest(ctx framework.TestContext, ns, mani string) {
   ctx.Logf(">>> Applying to namespace %q manifest:\n%s", ns, mani)
   dir := ctx.CreateTmpDirectoryOrFail("kmesh-lb")
   path := filepath.Join(dir, "m.yaml")
   if err := os.WriteFile(path, []byte(mani), 0644); err != nil {
     ctx.Fatalf("WriteFile(%s) failed: %v", path, err)
   }
   content, _ := os.ReadFile(path)
   ctx.Logf(">>> On-disk manifest at %s:\n%s", path, content)
   runCommand(ctx, fmt.Sprintf("kubectl apply -n %s -f %s", ns, path))
 }

 func getClusterIP(ctx framework.TestContext, ns, svc string) string {
   ip := runCommand(ctx, fmt.Sprintf(
     "kubectl get svc %s -n %s -o jsonpath={.spec.clusterIP}", svc, ns))
   if ip == "" {
     ctx.Fatalf("Empty ClusterIP for %s/%s", ns, svc)
   }
   if strings.Contains(ip, ":") {
     ip = "[" + ip + "]"
   }
   ctx.Logf("ClusterIP for %s/%s = %s", ns, svc, ip)
   return ip
 }
 
 func getSleepPod(ctx framework.TestContext, ns string) string {
   pod := runCommand(ctx, fmt.Sprintf(
     "kubectl get pod -n %s -l app=sleep -o jsonpath={.items[0].metadata.name}", ns))
   if pod == "" {
     ctx.Fatalf("No sleep pod found in %s", ns)
   }
   ctx.Logf("sleep pod = %s", pod)
   return pod
 }
 
 func waitForDeployment(ctx framework.TestContext, ns, name string) {
   runCommand(ctx, fmt.Sprintf(
     "kubectl wait --for=condition=available deployment/%s -n %s --timeout=120s",
     name, ns))
 }
 
 func curlHello(ctx framework.TestContext, ns, pod, fqdn, ip string) (string, error) {
   cmd := fmt.Sprintf(
     "kubectl exec -n %s %s -- curl -sSL -v --resolve %s:5000:%s http://%s:5000/hello",
     ns, pod, fqdn, ip, fqdn)
   return shell.Execute(false, cmd)
 }
 
 // Test 1: PreferClose via annotation
 func TestLocality_PreferClose_Annotation(t *testing.T) {
   framework.NewTest(t).Run(func(ctx framework.TestContext) {
     // Label nodes subzone1 (worker) & subzone2 (control-plane)
     runCommand(ctx, "kubectl label node kmesh-testing-worker topology.kubernetes.io/region=region topology.kubernetes.io/zone=zone1 topology.kubernetes.io/subzone=subzone1 --overwrite")
     runCommand(ctx, "kubectl label node kmesh-testing-control-plane topology.kubernetes.io/region=region topology.kubernetes.io/zone=zone1 topology.kubernetes.io/subzone=subzone2 --overwrite")
 
     ns, svc := "sample-pc-annot", "helloworld"
     fqdn := svc + "." + ns + ".svc.cluster.local"
     localVer, remoteVer := "sub1", "sub2"
 
     runCommand(ctx, "kubectl create namespace "+ns)
 
     // Service with PreferClose via annotation
     applyManifest(ctx, ns, fmt.Sprintf(`
 apiVersion: v1
 kind: Service
 metadata:
   name: %s
   namespace: %s
   annotations:
     networking.istio.io/traffic-distribution: PreferClose
   labels:
     app: helloworld
 spec:
   selector:
     app: helloworld
   ports:
   - name: http
     port: 5000
     targetPort: 5000
 `, svc, ns))
 
     // Local deployment (sub1) on worker
     applyManifest(ctx, ns, fmt.Sprintf(`
 apiVersion: apps/v1
 kind: Deployment
 metadata:
   name: helloworld-%s
   namespace: %s
   labels:
     app: helloworld
     version: %s
 spec:
   replicas: 1
   selector:
     matchLabels:
       app: helloworld
       version: %s
   template:
     metadata:
       labels:
         app: helloworld
         version: %s
     spec:
       nodeSelector:
         kubernetes.io/hostname: kmesh-testing-worker
       containers:
       - name: helloworld
         image: docker.io/istio/examples-helloworld-v1
         imagePullPolicy: IfNotPresent
         env:
         - name: SERVICE_VERSION
           value: %s
         ports:
         - containerPort: 5000
 `, localVer, ns, localVer, localVer, localVer, localVer))
 
     // Remote deployment (sub2) on control-plane (with toleration)
     applyManifest(ctx, ns, fmt.Sprintf(`
 apiVersion: apps/v1
 kind: Deployment
 metadata:
   name: helloworld-%s
   namespace: %s
   labels:
     app: helloworld
     version: %s
 spec:
   replicas: 1
   selector:
     matchLabels:
       app: helloworld
       version: %s
   template:
     metadata:
       labels:
         app: helloworld
         version: %s
     spec:
       nodeSelector:
         kubernetes.io/hostname: kmesh-testing-control-plane
       tolerations:
       - key: "node-role.kubernetes.io/control-plane"
         operator: "Exists"
         effect: NoSchedule
       containers:
       - name: helloworld
         image: docker.io/istio/examples-helloworld-v1
         imagePullPolicy: IfNotPresent
         env:
         - name: SERVICE_VERSION
           value: %s
         ports:
         - containerPort: 5000
 `, remoteVer, ns, remoteVer, remoteVer, remoteVer, remoteVer))
 
     // Sleep client on worker
     applyManifest(ctx, ns, fmt.Sprintf(`
 apiVersion: apps/v1
 kind: Deployment
 metadata:
   name: sleep
   namespace: %s
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
       nodeSelector:
         kubernetes.io/hostname: kmesh-testing-worker
       containers:
       - name: sleep
         image: curlimages/curl
         command: ["/bin/sleep","infinity"]
 `, ns))
 
     waitForDeployment(ctx, ns, "helloworld-"+localVer)
     waitForDeployment(ctx, ns, "helloworld-"+remoteVer)
     waitForDeployment(ctx, ns, "sleep")
 
     ip := getClusterIP(ctx, ns, svc)
     pod := getSleepPod(ctx, ns)
 
     // Expect only local → no remote yet
     sawLocal := false
     for i := 0; i < 10; i++ {
       out, _ := curlHello(ctx, ns, pod, fqdn, ip)
       ctx.Logf("curl #%d → %q", i+1, out)
       if strings.Contains(out, remoteVer) {
         ctx.Fatalf("remote seen before deletion: %q", out)
       }
       if strings.Contains(out, localVer) {
         sawLocal = true
         break
       }
       time.Sleep(2 * time.Second)
     }
     if !sawLocal {
       ctx.Fatalf("never saw local (%q)", localVer)
     }
 
     // Delete local → should fail over to remote
     runCommand(ctx, "kubectl delete deployment helloworld-"+localVer+" -n "+ns)
     retry.UntilSuccessOrFail(ctx, func() error {
       out, _ := curlHello(ctx, ns, pod, fqdn, ip)
       if !strings.Contains(out, remoteVer) {
         return fmt.Errorf("still not remote: %q", out)
       }
       return nil
     }, retry.Timeout(60*time.Second), retry.Delay(2*time.Second))
   })
 }
 
 // Test 2: Local strict via internalTrafficPolicy: Local
 func TestLocality_LocalStrict(t *testing.T) {
   framework.NewTest(t).Run(func(ctx framework.TestContext) {
     runCommand(ctx, "kubectl label node kmesh-testing-worker topology.kubernetes.io/region=region topology.kubernetes.io/zone=zone1 topology.kubernetes.io/subzone=subzone1 --overwrite")
     runCommand(ctx, "kubectl label node kmesh-testing-control-plane topology.kubernetes.io/region=region topology.kubernetes.io/zone=zone1 topology.kubernetes.io/subzone=subzone2 --overwrite")
 
     ns, svc := "sample-local", "helloworld"
     fqdn := svc + "." + ns + ".svc.cluster.local"
     localVer, remoteVer := "sub1", "sub2"
 
     runCommand(ctx, "kubectl create namespace "+ns)
 
     // Service in strict Local mode
     applyManifest(ctx, ns, fmt.Sprintf(`
 apiVersion: v1
 kind: Service
 metadata:
   name: %s
   namespace: %s
   labels:
     app: helloworld
 spec:
   selector:
     app: helloworld
   ports:
   - name: http
     port: 5000
     targetPort: 5000
   internalTrafficPolicy: Local
 `, svc, ns))
 
     // Local deployment
     applyManifest(ctx, ns, fmt.Sprintf(`
 apiVersion: apps/v1
 kind: Deployment
 metadata:
   name: helloworld-%s
   namespace: %s
   labels:
     app: helloworld
     version: %s
 spec:
   replicas: 1
   selector:
     matchLabels:
       app: helloworld
       version: %s
   template:
     metadata:
       labels:
         app: helloworld
         version: %s
     spec:
       nodeSelector:
         kubernetes.io/hostname: kmesh-testing-worker
       containers:
       - name: helloworld
         image: docker.io/istio/examples-helloworld-v1
         imagePullPolicy: IfNotPresent
         env:
         - name: SERVICE_VERSION
           value: %s
         ports:
         - containerPort: 5000
 `, localVer, ns, localVer, localVer, localVer, localVer))
 
     // Remote deployment (to prove strict mode blocks it)
     applyManifest(ctx, ns, fmt.Sprintf(`
 apiVersion: apps/v1
 kind: Deployment
 metadata:
   name: helloworld-%s
   namespace: %s
   labels:
     app: helloworld
     version: %s
 spec:
   replicas: 1
   selector:
     matchLabels:
       app: helloworld
       version: %s
   template:
     metadata:
       labels:
         app: helloworld
         version: %s
     spec:
       nodeSelector:
         kubernetes.io/hostname: kmesh-testing-control-plane
       tolerations:
       - key: "node-role.kubernetes.io/control-plane"
         operator: "Exists"
         effect: NoSchedule
       containers:
       - name: helloworld
         image: docker.io/istio/examples-helloworld-v1
         imagePullPolicy: IfNotPresent
         env:
         - name: SERVICE_VERSION
           value: %s
         ports:
         - containerPort: 5000
 `, remoteVer, ns, remoteVer, remoteVer, remoteVer, remoteVer))
 
     // Sleep client
     applyManifest(ctx, ns, fmt.Sprintf(`
 apiVersion: apps/v1
 kind: Deployment
 metadata:
   name: sleep
   namespace: %s
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
       nodeSelector:
         kubernetes.io/hostname: kmesh-testing-worker
       containers:
       - name: sleep
         image: curlimages/curl
         command: ["/bin/sleep","infinity"]
 `, ns))
 
     waitForDeployment(ctx, ns, "helloworld-"+localVer)
     waitForDeployment(ctx, ns, "helloworld-"+remoteVer)
     waitForDeployment(ctx, ns, "sleep")
 
     pod := getSleepPod(ctx, ns)
     ip := getClusterIP(ctx, ns, svc)
 
     // Must initially hit local
     out, _ := curlHello(ctx, ns, pod, fqdn, ip)
     if !strings.Contains(out, localVer) {
       ctx.Fatalf("Local strict initial: expected %q, got %q", localVer, out)
     }
 
     // Delete local → should now fail (no remote fallback)
     runCommand(ctx, "kubectl delete deployment helloworld-"+localVer+" -n "+ns)
     time.Sleep(5 * time.Second)
     if out, err := curlHello(ctx, ns, pod, fqdn, ip); err == nil {
       ctx.Fatalf("Local strict should fail, but got %q", out)
     }
   })
 }
 
 // Test 3: Subzone distribution across two fallback pods
 func TestLocality_SubzoneDistribution(t *testing.T) {
   framework.NewTest(t).Run(func(ctx framework.TestContext) {
     runCommand(ctx, "kubectl label node kmesh-testing-worker topology.kubernetes.io/region=region topology.kubernetes.io/zone=zone1 topology.kubernetes.io/subzone=subzone1 --overwrite")
     runCommand(ctx, "kubectl label node kmesh-testing-control-plane topology.kubernetes.io/region=region topology.kubernetes.io/zone=zone1 topology.kubernetes.io/subzone=subzone2 --overwrite")
 
     ns, svc := "sample-dist", "helloworld"
     fqdn := svc + "." + ns + ".svc.cluster.local"
     localVer := "sub1"
     rem1, rem2 := "sub2-a", "sub2-b"
 
     runCommand(ctx, "kubectl create namespace "+ns)
 
     // Service again via annotation
     applyManifest(ctx, ns, fmt.Sprintf(`
 apiVersion: v1
 kind: Service
 metadata:
   name: %s
   namespace: %s
   annotations:
     networking.istio.io/traffic-distribution: PreferClose
   labels:
     app: helloworld
 spec:
   selector:
     app: helloworld
   ports:
   - name: http
     port: 5000
     targetPort: 5000
 `, svc, ns))
 
     // Local
     applyManifest(ctx, ns, fmt.Sprintf(`
 apiVersion: apps/v1
 kind: Deployment
 metadata:
   name: helloworld-%s
   namespace: %s
   labels:
     app: helloworld
     version: %s
 spec:
   replicas: 1
   selector:
     matchLabels:
       app: helloworld
       version: %s
   template:
     metadata:
       labels:
         app: helloworld
         version: %s
     spec:
       nodeSelector:
         kubernetes.io/hostname: kmesh-testing-worker
       containers:
       - name: helloworld
         image: docker.io/istio/examples-helloworld-v1
         env:
         - name: SERVICE_VERSION
           value: %s
         ports:
         - containerPort: 5000
 `, localVer, ns, localVer, localVer, localVer, localVer))
 
     // Two fallback (lowercase!)
     for _, v := range []string{rem1, rem2} {
       applyManifest(ctx, ns, fmt.Sprintf(`
 apiVersion: apps/v1
 kind: Deployment
 metadata:
   name: helloworld-%s
   namespace: %s
   labels:
     app: helloworld
     version: %s
 spec:
   replicas: 1
   selector:
     matchLabels:
       app: helloworld
       version: %s
   template:
     metadata:
       labels:
         app: helloworld
         version: %s
     spec:
       nodeSelector:
         kubernetes.io/hostname: kmesh-testing-control-plane
       tolerations:
       - key: "node-role.kubernetes.io/control-plane"
         operator: "Exists"
         effect: NoSchedule
       containers:
       - name: helloworld
         image: docker.io/istio/examples-helloworld-v1
         env:
         - name: SERVICE_VERSION
           value: %s
         ports:
         - containerPort: 5000
 `, v, ns, v, v, v, v))
     }
 
     // Sleep client
     applyManifest(ctx, ns, fmt.Sprintf(`
 apiVersion: apps/v1
 kind: Deployment
 metadata:
   name: sleep
   namespace: %s
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
       nodeSelector:
         kubernetes.io/hostname: kmesh-testing-worker
       containers:
       - name: sleep
         image: curlimages/curl
         command: ["/bin/sleep","infinity"]
 `, ns))
 
     waitForDeployment(ctx, ns, "helloworld-"+localVer)
     waitForDeployment(ctx, ns, "helloworld-"+rem1)
     waitForDeployment(ctx, ns, "helloworld-"+rem2)
     waitForDeployment(ctx, ns, "sleep")
 
     // Delete local → exercise distribution
     runCommand(ctx, "kubectl delete deployment helloworld-"+localVer+" -n "+ns)
     ip := getClusterIP(ctx, ns, svc)
     pod := getSleepPod(ctx, ns)
 
     counts := map[string]int{}
     for i := 0; i < 20; i++ {
       out, _ := curlHello(ctx, ns, pod, fqdn, ip)
       for _, v := range []string{rem1, rem2} {
         if strings.Contains(out, v) {
           counts[v]++
         }
       }
       time.Sleep(200 * time.Millisecond)
     }
     ctx.Logf("Distribution: %+v", counts)
     if counts[rem1] == 0 || counts[rem2] == 0 {
       ctx.Fatalf("Expected both %q and %q, got %+v", rem1, rem2, counts)
     }
   })
 }
 