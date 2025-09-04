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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"istio.io/istio/pkg/test/framework"
	"os/exec"
	"strings"
	"testing"
	"time"
)

var sleepYaml = `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sleep
---
apiVersion: v1
kind: Service
metadata:
  name: sleep
  labels:
    app: sleep
    service: sleep
spec:
  ports:
  - port: 80
    name: http
  selector:
    app: sleep
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sleep
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
      terminationGracePeriodSeconds: 0
      serviceAccountName: sleep
      nodeName: kmesh-testing-control-plane
      containers:
      - name: sleep
        image: curlimages/curl
        command: ["/bin/sleep", "infinity"]
        imagePullPolicy: IfNotPresent
        volumeMounts:
        - mountPath: /etc/sleep/tls
          name: secret-volume
      volumes:
      - name: secret-volume
        secret:
          secretName: sleep-secret
          optional: true
`

var httpbinYaml = `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: httpbin
---
apiVersion: v1
kind: Service
metadata:
  name: httpbin
  labels:
    app: httpbin
    service: httpbin
spec:
  ports:
  - name: http
    port: 8000
    targetPort: 80
  selector:
    app: httpbin
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: httpbin
spec:
  replicas: 1
  selector:
    matchLabels:
      app: httpbin
      version: v1
  template:
    metadata:
      labels:
        app: httpbin
        version: v1
    spec:
      serviceAccountName: httpbin
      nodeName: kmesh-testing-worker
      containers:
      - image: docker.io/kong/httpbin
        imagePullPolicy: IfNotPresent
        name: httpbin
        ports:
        - containerPort: 80
`

func deployServices(t framework.TestContext) error {
	t.Logf("Labeling namespace...")
	cmd := exec.Command("kubectl", "label", "namespace", "default", "istio.io/dataplane-mode=Kmesh")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to label namespace: %s\n%s", err, string(out))
		return err
	}

	t.Logf("Applying sleep resources...")
	cmd = exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(sleepYaml)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to apply sleep resources: %s\n%s", err, string(out))
		return err
	}

	t.Logf("Applying httpbin resources...")
	cmd = exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(httpbinYaml)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to apply httpbin resources: %s\n%s", err, string(out))
		return err
	}

	return nil
}

func deleteServices(t framework.TestContext) error {
	t.Logf("Deleting sleep resources...")
	cmd := exec.Command("kubectl", "delete", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(sleepYaml)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to delete sleep resources: %s\n%s", err, string(out))
		return err
	}

	t.Logf("Deleting httpbin resources...")
	cmd = exec.Command("kubectl", "delete", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(httpbinYaml)
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to delete httpbin resources: %s\n%s", err, string(out))
		return err
	}

	t.Logf("Removing label from namespace default...")
	cmd = exec.Command("kubectl", "label", "namespace", "default", "istio.io/dataplane-mode-")
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to remove label: %s\n%s", err, string(out))
		return err
	}

	return nil
}

func getPodNameAndIP(t framework.TestContext, appLabel string) (string, string, error) {
	for {
		cmd := exec.Command("kubectl", "get", "pods", "-l", "app="+appLabel, "-o", "wide")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("kubectl get pods failed: %v\n%s", err, string(out))
			time.Sleep(3 * time.Second)
			continue
		}
		lines := strings.Split(string(out), "\n")
		if len(lines) < 2 {
			t.Logf("no pods found for app=%s, retrying...", appLabel)
			time.Sleep(3 * time.Second)
			continue
		}
		fields := strings.Fields(lines[1])
		if len(fields) < 6 {
			t.Logf("unexpected kubectl output format, retrying...")
			time.Sleep(3 * time.Second)
			continue
		}
		// fields[2] 是 pod 状态
		if fields[2] == "Running" {
			podName := fields[0]
			podIP := fields[5]
			if podIP != "" && podIP != "<none>" {
				return podName, podIP, nil
			}
			t.Logf("Pod %s is Running but IP not assigned yet, waiting...", podName)
		} else {
			t.Logf("Pod %s status: %s, waiting for Running...", fields[0], fields[2])
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
	if !strings.Contains(stateStr, "sel src 0.0.0.0/0 dst 0.0.0.0/0") {
		t.Fatalf("ip xfrm state output does not contain expected selector")
		return fmt.Errorf("ip xfrm state output does not contain expected selector")
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

func curlFromSleepToHttpbin(t framework.TestContext, sleepPod, httpbinIP string) (string, error) {
	cmd := exec.Command("kubectl", "exec", sleepPod, "--", "curl", fmt.Sprintf("http://%s:80", httpbinIP))
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

func rotateIPSecKeyAndWait(t framework.TestContext, containerName string, maxRetry int, intervalSec int) error {
	t.Logf("Rotating IPSec key with kmeshctl secret ...")
	keyHex := genRandomKeyHex()
	rotateCmd := exec.Command("kmeshctl", "secret", "create", "--key="+keyHex)
	out, err := rotateCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to rotate IPSec key: %v\n%s", err, string(out))
		return err
	}
	t.Logf("kmeshctl secret update success")

	t.Logf("Waiting for SPI 0x00000002 to appear (max %d retries, interval %ds)...", maxRetry, intervalSec)
	for i := 0; i < maxRetry; i++ {
		time.Sleep(time.Duration(intervalSec) * time.Second)
		stateCmd := exec.Command("docker", "exec", containerName, "bash", "-c", "ip xfrm state")
		stateOut, err := stateCmd.CombinedOutput()
		if err != nil {
			t.Logf("ip xfrm state failed: %v\n%s", err, string(stateOut))
			continue
		}
		if strings.Contains(string(stateOut), "spi 0x00000002") {
			t.Logf("Found new SPI 0x00000002 in ip xfrm state!")
			return nil
		}
		t.Logf("SPI 0x00000002 not found, retry %d/%d...", i+1, maxRetry)
	}
	t.Fatalf("SPI 0x00000002 not found after %d retries", maxRetry)
	return fmt.Errorf("SPI 0x00000002 not found after %d retries", maxRetry)
}

func TestIPsecAuthorization(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		t.NewSubTest("IPsec Authorization").Run(func(t framework.TestContext) {

			if err := deployServices(t); err != nil {
				return
			}

			t.Logf("Resources applied. You can now continue with IPSec validation.")

			sleepPodName, sleepPodIP, err := getPodNameAndIP(t, "sleep")
			if err != nil {
				return
			} else {
				t.Logf("sleep pod name: %s, ip: %s", sleepPodName, sleepPodIP)
			}

			httpbinPodName, httpbinPodIP, err := getPodNameAndIP(t, "httpbin")
			if err != nil {
				return
			} else {
				t.Logf("httpbin pod name: %s, ip: %s", httpbinPodName, httpbinPodIP)
			}

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
			t.Logf("Curling from sleep pod to httpbin pod...")
			curlOut, err := curlFromSleepToHttpbin(t, sleepPodName, httpbinPodIP)
			if err != nil {
				<-tcpdumpCh
				deleteServices(t)
				return
			}
			t.Logf("curl success")
			tcpdumpOut := <-tcpdumpCh

			if strings.Contains(tcpdumpOut, "ESP") {
				t.Logf("Test success: ESP packets detected during curl!")
			} else {
				t.Fatalf("Test failed: No ESP packets detected.")
			}

			if err = rotateIPSecKeyAndWait(t, "kmesh-testing-control-plane", 20, 5); err != nil {
				deleteServices(t)
				return
			}

			t.Logf("Starting tcpdump in kmesh-testing-control-plane container after key rotation...")
			tcpdumpCh = make(chan string)
			go func() {
				out, _ := runTcpdumpESP(t, "kmesh-testing-control-plane", 10)
				tcpdumpCh <- out
			}()
			time.Sleep(2 * time.Second)
			t.Logf("Curling from sleep pod to httpbin pod after key rotation...")
			curlOut, err = curlFromSleepToHttpbin(t, sleepPodName, httpbinPodIP)
			if err != nil {
				<-tcpdumpCh
				deleteServices(t)
				return
			}
			t.Logf("Curl output after key rotation: %s", curlOut)
			tcpdumpOut = <-tcpdumpCh
			t.Logf("tcpdump output after key rotation:\n%s", tcpdumpOut)

			if strings.Contains(tcpdumpOut, "ESP") && strings.Contains(tcpdumpOut, "spi=0x00000002") {
				t.Logf("Test success: ESP packets with new SPI detected after key rotation!")
			} else {
				t.Fatalf("Test failed: No ESP packets with new SPI detected after key rotation.")
			}

			if err := deleteServices(t); err != nil {
				return
			}
			t.Logf("Resources deleted.")

		})
	})
}
