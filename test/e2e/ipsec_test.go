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
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"istio.io/istio/pkg/test/framework"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os/exec"
	"strings"
	"testing"
	"text/template"
	"time"
)

type DeployParams struct {
	Name          string
	AppLabel      string
	Image         string
	NodeName      string
	SvcPort       int
	TargetPort    int
	ContainerPort int
}

var sleepTmpl = `
apiVersion: v1
kind: Service
metadata:
  name: {{.Name}}
  labels:
    app: {{.AppLabel}}
    service: {{.AppLabel}}
spec:
  ports:
  - port: 80
    name: http
  selector:
    app: {{.AppLabel}}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{.Name}}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {{.AppLabel}}
  template:
    metadata:
      labels:
        app: {{.AppLabel}}
    spec:
      nodeName: {{.NodeName}}
      containers:
      - name: {{.Name}}
        image: {{.Image}}
        command: ["/bin/sleep", "infinity"]
        imagePullPolicy: IfNotPresent
`

var echoTmpl = `
apiVersion: v1
kind: Service
metadata:
  name: {{.Name}}
  namespace: default
spec:
  ports:
  - name: http
    port: {{.SvcPort}}
    targetPort: {{.TargetPort}}
  selector:
    app: {{.AppLabel}}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{.Name}}
  namespace: default
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {{.AppLabel}}
  template:
    metadata:
      labels:
        app: {{.AppLabel}}
    spec:
      containers:
      - name: {{.Name}}
        image: {{.Image}}
        imagePullPolicy: IfNotPresent
        args:
        - --port={{.ContainerPort}}
        ports:
        - containerPort: {{.ContainerPort}}
`

func labelNamespace(t framework.TestContext, namespace, key, value string) error {
	var cmd *exec.Cmd
	if value == "" {
		cmd = exec.Command("kubectl", "label", "namespace", namespace, key+"-")
	} else {
		cmd = exec.Command("kubectl", "label", "namespace", namespace, key+"="+value, "--overwrite")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl label namespace failed: %v\n%s", err, string(out))
		return err
	}
	t.Logf("namespace %s label set: %s=%s", namespace, key, value)
	return nil
}

func deployService(t framework.TestContext, tmplText string, params DeployParams) error {
	tmpl, err := template.New("yaml").Parse(tmplText)
	if err != nil {
		t.Fatalf("failed to parse template: %v", err)
		return err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, params); err != nil {
		t.Fatalf("failed to execute template: %v", err)
		return err
	}
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = &buf
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl apply failed: %v\n%s", err, string(out))
		return err
	}
	t.Logf("applied resources for %s:\n%s", params.Name, string(out))
	return nil
}

func deleteService(t framework.TestContext, name, namespace string) error {
	t.Logf("Deleting deployment and service %s in namespace %s...", name, namespace)
	cmd := exec.Command("kubectl", "delete", "deployment,service", name, "-n", namespace)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Failed to delete %s: %v\n%s", name, err, string(out))
		return err
	}
	t.Logf("Deleted %s: %s", name, string(out))
	return nil
}

func getPodNameAndIP(t framework.TestContext, namespace string, appLabel string) (string, string, error) {
	client := t.Clusters().Default().Kube().CoreV1().Pods(namespace)
	selector := "app=" + appLabel

	for {
		podList, err := client.List(context.TODO(), metav1.ListOptions{LabelSelector: selector})
		if err != nil {
			t.Logf("list pods failed: %v, retrying...", err)
			time.Sleep(3 * time.Second)
			continue
		}
		if len(podList.Items) == 0 {
			t.Logf("no pods found for app=%s, retrying...", appLabel)
			time.Sleep(3 * time.Second)
			continue
		}
		for _, p := range podList.Items {
			if p.Status.Phase == corev1.PodRunning && p.Status.PodIP != "" && p.Status.PodIP != "<none>" {
				return p.Name, p.Status.PodIP, nil
			}
			t.Logf("pod %s status=%s ip=%s, waiting...", p.Name, p.Status.Phase, p.Status.PodIP)
		}
		time.Sleep(3 * time.Second)
	}
}

func downloadTcpdump(t framework.TestContext, containerName string) error {
	checkCmd := exec.Command("docker", "exec", containerName, "bash", "-c", "which tcpdump")
	out, err := checkCmd.CombinedOutput()
	if err == nil && strings.TrimSpace(string(out)) != "" {
		t.Logf("tcpdump is already installed in container: %s", containerName)
		return nil
	}
	t.Logf("tcpdump not found, installing in container: %s", containerName)

	updateCmd := exec.Command("docker", "exec", containerName, "bash", "-c", "apt update")
	out, err = updateCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("apt update failed: %v\n%s", err, string(out))
		return err
	}
	t.Logf("apt update success")

	installCmd := exec.Command("docker", "exec", containerName, "bash", "-c", "apt install tcpdump -y")
	out, err = installCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("apt install tcpdump failed: %v\n%s", err, string(out))
		return err
	}
	t.Logf("apt install tcpdump success")
	return nil
}

func checkIPSecRules(t framework.TestContext, containerName string) error {
	stateCmd := exec.Command("docker", "exec", containerName, "bash", "-c", "ip xfrm state")
	stateOut, err := stateCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run ip xfrm state: %v\n%s", err, string(stateOut))
		return err
	}
	t.Logf("ip xfrm state output:\n%s", string(stateOut))

	policyCmd := exec.Command("docker", "exec", containerName, "bash", "-c", "ip xfrm policy")
	policyOut, err := policyCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run ip xfrm policy: %v\n%s", err, string(policyOut))
		return err
	}
	t.Logf("ip xfrm policy output:\n%s", string(policyOut))

	stateStr := string(stateOut)
	policyStr := string(policyOut)

	if !strings.Contains(stateStr, "proto esp spi") || !strings.Contains(stateStr, "mode tunnel") {
		t.Fatalf("ip xfrm state output does not contain expected ESP tunnel rules")
		return fmt.Errorf("ip xfrm state output does not contain expected ESP tunnel rules")
	}
	if !strings.Contains(stateStr, "aead rfc4106(gcm(aes))") {
		t.Fatalf("ip xfrm state output does not contain expected AEAD algorithm")
		return fmt.Errorf("ip xfrm state output does not contain expected AEAD algorithm")
	}

	if !strings.Contains(policyStr, "tmpl src") || !strings.Contains(policyStr, "proto esp") || !strings.Contains(policyStr, "mode tunnel") {
		t.Fatalf("ip xfrm policy output does not contain expected tunnel template")
		return fmt.Errorf("ip xfrm policy output does not contain expected tunnel template")
	}
	if !strings.Contains(policyStr, "dir out") || !strings.Contains(policyStr, "dir in") || !strings.Contains(policyStr, "dir fwd") {
		t.Fatalf("ip xfrm policy output does not contain expected directions (out/in/fwd)")
		return fmt.Errorf("ip xfrm policy output does not contain expected directions (out/in/fwd)")
	}
	if !strings.Contains(policyStr, "mark") {
		t.Fatalf("ip xfrm policy output does not contain expected mark field")
		return fmt.Errorf("ip xfrm policy output does not contain expected mark field")
	}

	t.Logf("IPSec xfrm state and policy outputs match expected format.")
	return nil
}

func runTcpdumpESP(t framework.TestContext, containerName string, duration int) (string, error) {
	cmd := exec.Command("docker", "exec", containerName, "bash", "-c",
		fmt.Sprintf("timeout %d tcpdump -i any | grep ESP", duration))
	out, err := cmd.CombinedOutput()
	if err != nil && !strings.Contains(err.Error(), "exit status 124") {
		t.Fatalf("tcpdump failed: %v\n%s", err, string(out))
		return "", err
	}
	return string(out), nil
}

func curlFromSleepToEcho(t framework.TestContext, sleepPod, echoIP string, echoPort int) (string, error) {
	t.Logf("Curling from sleep pod %s to echo pod IP %s...", sleepPod, echoIP)
	var url string
	if strings.Contains(echoIP, ":") {
		// IPv6 address
		url = fmt.Sprintf("http://[%s]:%d", echoIP, echoPort)
	} else {
		// IPv4 address
		url = fmt.Sprintf("http://%s:%d", echoIP, echoPort)
	}
	cmd := exec.Command("kubectl", "exec", sleepPod, "--", "curl", url)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("curl failed: %v\n%s", err, string(out))
		return "", err
	}
	return string(out), nil
}

func genRandomKeyHex() string {
	b := make([]byte, 36)
	_, err := rand.Read(b)
	if err != nil {
		panic("failed to generate random key")
	}
	return hex.EncodeToString(b)
}

func rotateIPSecKeyAndWait(t framework.TestContext, containerName string, intervalSec int) error {
	t.Logf("Rotating IPSec key with kmeshctl secret ...")
	keyHex := genRandomKeyHex()
	rotateCmd := exec.Command("kmeshctl", "secret", "create", "--key="+keyHex)
	out, err := rotateCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to rotate IPSec key: %v\n%s", err, string(out))
		return err
	}
	t.Logf("kmeshctl secret update success")

	t.Logf("Waiting for SPI 0x00000002 to appear in both state and policy (interval %ds)...", intervalSec)
	for {
		time.Sleep(time.Duration(intervalSec) * time.Second)
		stateCmd := exec.Command("docker", "exec", containerName, "bash", "-c", "ip xfrm state")
		stateOut, err := stateCmd.CombinedOutput()
		if err != nil {
			t.Logf("ip xfrm state failed: %v\n%s", err, string(stateOut))
			continue
		}
		policyCmd := exec.Command("docker", "exec", containerName, "bash", "-c", "ip xfrm policy")
		policyOut, err := policyCmd.CombinedOutput()
		if err != nil {
			t.Logf("ip xfrm policy failed: %v\n%s", err, string(policyOut))
			continue
		}
		stateHasSPI := strings.Contains(string(stateOut), "spi 0x00000002")
		policyHasSPI := strings.Contains(string(policyOut), "spi 0x00000002")
		if stateHasSPI && policyHasSPI {
			t.Logf("Found new SPI 0x00000002 in both ip xfrm state and policy!")
			return nil
		}
		t.Logf("SPI 0x00000002 not found in both state and policy, waiting...")
	}
}

func TestIPsec(t *testing.T) {
	secretCmd := exec.Command("kmeshctl", "secret", "create")
	out, err := secretCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to rotate IPSec key: %v\n%s", err, string(out))
		return
	}

	// wait until both ip xfrm state and policy are non-empty before continuing
	for {
		stateCmd := exec.Command("docker", "exec", "kmesh-testing-control-plane", "bash", "-c", "ip xfrm state")
		stateOut, _ := stateCmd.CombinedOutput()

		policyCmd := exec.Command("docker", "exec", "kmesh-testing-control-plane", "bash", "-c", "ip xfrm policy")
		policyOut, _ := policyCmd.CombinedOutput()

		if strings.TrimSpace(string(stateOut)) != "" && strings.TrimSpace(string(policyOut)) != "" {
			t.Logf("ip xfrm state and policy populated")
			break
		}

		t.Logf("waiting for ip xfrm state/policy to be populated (stateLen=%d policyLen=%d)...", len(stateOut), len(policyOut))
		time.Sleep(3 * time.Second)
	}

	framework.NewTest(t).Run(func(t framework.TestContext) {
		t.NewSubTest("IPsec Connectivity").Run(func(t framework.TestContext) {

			// prepare params
			if err := labelNamespace(t, "default", "istio.io/dataplane-mode", "Kmesh"); err != nil {
				return
			}
			sleepParams := DeployParams{
				Name:     "sleep-1",
				AppLabel: "sleep-1",
				Image:    "curlimages/curl",
				NodeName: "kmesh-testing-control-plane",
			}
			echoParams := DeployParams{
				Name:          "echo-1",
				AppLabel:      "echo-1",
				Image:         "gcr.io/istio-testing/app:latest",
				SvcPort:       80,
				TargetPort:    8080,
				ContainerPort: 8080,
			}

			// deploy
			if err := deployService(t, sleepTmpl, sleepParams); err != nil {
				return
			}
			if err := deployService(t, echoTmpl, echoParams); err != nil {
				_ = deleteService(t, sleepParams.Name, "default")
				return
			}

			// cleanup
			t.Cleanup(func() {
				_ = deleteService(t, sleepParams.Name, "default")
				_ = deleteService(t, echoParams.Name, "default")
				_ = labelNamespace(t, "default", "istio.io/dataplane-mode", "")
			})

			t.Logf("Resources applied. Waiting for pods...")

			sleepPodName, sleepPodIP, err := getPodNameAndIP(t, "default", sleepParams.AppLabel)
			if err != nil {
				return
			}
			t.Logf("sleep pod name: %s, ip: %s", sleepPodName, sleepPodIP)

			echoPodName, echoPodIP, err := getPodNameAndIP(t, "default", echoParams.AppLabel)
			if err != nil {
				return
			}
			t.Logf("echo pod name: %s, ip: %s", echoPodName, echoPodIP)

			if err = downloadTcpdump(t, "kmesh-testing-control-plane"); err != nil {
				return
			}
			if err = checkIPSecRules(t, "kmesh-testing-control-plane"); err != nil {
				return
			}

			t.Logf("Starting tcpdump in kmesh-testing-control-plane container...")
			tcpdumpCh := make(chan string)
			go func() {
				out, _ := runTcpdumpESP(t, "kmesh-testing-control-plane", 10)
				tcpdumpCh <- out
			}()
			time.Sleep(2 * time.Second)

			t.Logf("Curling from sleep pod to echo pod...")
			_, err = curlFromSleepToEcho(t, sleepPodName, echoPodIP, echoParams.ContainerPort)
			if err != nil {
				<-tcpdumpCh
				return
			}
			t.Logf("curl success")
			tcpdumpOut := <-tcpdumpCh

			if strings.Contains(tcpdumpOut, "ESP") {
				t.Logf("Connectivity test success: ESP packets detected during curl")
			} else {
				t.Fatalf("Connectivity test failed: No ESP packets detected.")
			}
		})
	})

	framework.NewTest(t).Run(func(t framework.TestContext) {
		t.NewSubTest("IPsec Key Rotation").Run(func(t framework.TestContext) {

			// prepare params
			if err := labelNamespace(t, "default", "istio.io/dataplane-mode", "Kmesh"); err != nil {
				return
			}
			sleepParams := DeployParams{
				Name:     "sleep-2",
				AppLabel: "sleep-2",
				Image:    "curlimages/curl",
				NodeName: "kmesh-testing-control-plane",
			}
			echoParams := DeployParams{
				Name:          "echo-2",
				AppLabel:      "echo-2",
				Image:         "gcr.io/istio-testing/app:latest",
				SvcPort:       80,
				TargetPort:    8080,
				ContainerPort: 8080,
			}

			// deploy
			if err := deployService(t, sleepTmpl, sleepParams); err != nil {
				return
			}
			if err := deployService(t, echoTmpl, echoParams); err != nil {
				_ = deleteService(t, sleepParams.Name, "default")
				return
			}

			// cleanup
			t.Cleanup(func() {
				_ = deleteService(t, sleepParams.Name, "default")
				_ = deleteService(t, echoParams.Name, "default")
				_ = labelNamespace(t, "default", "istio.io/dataplane-mode", "")
			})

			t.Logf("Resources applied. Waiting for pods...")

			sleepPodName, sleepPodIP, err := getPodNameAndIP(t, "default", sleepParams.AppLabel)
			if err != nil {
				return
			}
			t.Logf("sleep pod name: %s, ip: %s", sleepPodName, sleepPodIP)

			echoPodName, echoPodIP, err := getPodNameAndIP(t, "default", echoParams.AppLabel)
			if err != nil {
				return
			}
			t.Logf("echo pod name: %s, ip: %s", echoPodName, echoPodIP)

			if err = downloadTcpdump(t, "kmesh-testing-control-plane"); err != nil {
				return
			}
			if err = checkIPSecRules(t, "kmesh-testing-control-plane"); err != nil {
				return
			}

			// rotate key and wait for new SPI in both state and policy
			if err := rotateIPSecKeyAndWait(t, "kmesh-testing-control-plane", 5); err != nil {
				return
			}

			t.Logf("Starting tcpdump in kmesh-testing-control-plane container after key rotation...")
			tcpdumpCh := make(chan string)
			go func() {
				out, _ := runTcpdumpESP(t, "kmesh-testing-control-plane", 10)
				tcpdumpCh <- out
			}()
			time.Sleep(2 * time.Second)

			t.Logf("Curling from sleep pod to echo pod after key rotation...")
			_, err = curlFromSleepToEcho(t, sleepPodName, echoPodIP, echoParams.ContainerPort)
			if err != nil {
				<-tcpdumpCh
				return
			}
			t.Logf("curl after key rotation success")
			tcpdumpOut := <-tcpdumpCh
			t.Logf("tcpdump output after key rotation:\n%s", tcpdumpOut)

			if strings.Contains(tcpdumpOut, "ESP") && strings.Contains(tcpdumpOut, "spi=0x00000002") {
				t.Logf("Key rotation test success: ESP packets with new SPI detected after key rotation")
			} else {
				t.Fatalf("Key rotation test failed: No ESP packets with new SPI detected after key rotation.")
			}
		})
	})
}

func TestIPsecKeyRotation(t *testing.T) {

}
