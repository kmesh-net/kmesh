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
   "context"
   "crypto/rand"
   "encoding/hex"
   "encoding/json"
   "fmt"
   "os/exec"
   "testing"
   "time"


   v1 "k8s.io/api/core/v1"
   metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
   // Assume that utils.CreateKubeClient is available from your project.
   "kmesh.net/kmesh/ctl/utils"
)


// IpSecKey is a local representation of the IPsec key secret data that is stored in JSON.
// It contains the relevant fields; note that AeadKey is a byte slice.
type IpSecKey struct {
   AeadKeyName string `json:"AeadKeyName"`
   AeadKey     []byte `json:"AeadKey"`
   Length      int    `json:"Length"`
   Spi         int    `json:"Spi"`
}


// waitForSecret periodically retrieves the "kmesh-ipsec" secret from the specified namespace
// until it is found or the timeout is exceeded.
func waitForSecret(secretName, namespace string, timeout time.Duration) (*v1.Secret, error) {
   clientset, err := utils.CreateKubeClient()
   if err != nil {
       return nil, fmt.Errorf("failed to create kube client: %v", err)
   }


   deadline := time.Now().Add(timeout)
   for time.Now().Before(deadline) {
       sec, err := clientset.Kube().CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
       if err == nil {
           return sec, nil
       }
       time.Sleep(2 * time.Second)
   }
   return nil, fmt.Errorf("timeout waiting for secret %q in namespace %q", secretName, namespace)
}


// deleteSecret tries to delete the secret; if not found, it ignores the error.
func deleteSecret(secretName, namespace string) error {
   clientset, err := utils.CreateKubeClient()
   if err != nil {
       return fmt.Errorf("failed to create kube client: %v", err)
   }
   _ = clientset.Kube().CoreV1().Secrets(namespace).Delete(context.TODO(), secretName, metav1.DeleteOptions{})
   return nil
}


// generateRandomKey generates 36 random bytes and returns the hex-encoded string.
func generateRandomKey() (string, error) {
   keyBytes := make([]byte, 36)
   _, err := rand.Read(keyBytes)
   if err != nil {
       return "", fmt.Errorf("failed to generate random key: %v", err)
   }
   return hex.EncodeToString(keyBytes), nil
}


func TestKmeshctlSecret(t *testing.T) {
   const secretName = "kmesh-ipsec"
   const namespace = "kmesh-system"


   // Step 0: Pre-cleanup: delete existing secret if any.
   _ = deleteSecret(secretName, namespace)
   t.Log("Deleted existing secret (if any)")


   // Step 1: Create a new secret using a random key.
   key1, err := generateRandomKey()
   if err != nil {
       t.Fatalf("failed to generate random key: %v", err)
   }
   t.Logf("Generated key1: %s", key1)


   // Run the secret command.
   cmd := exec.Command("kmeshctl", "secret", "--key", key1)
   output, err := cmd.CombinedOutput()
   if err != nil {
       t.Fatalf("failed to run kmeshctl secret command: %v, output: %s", err, string(output))
   }
   t.Logf("Output of first 'kmeshctl secret' command: %s", string(output))


   // Step 2: Wait for the secret to be created.
   sec, err := waitForSecret(secretName, namespace, 30*time.Second)
   if err != nil {
       t.Fatalf("failed to get created secret: %v", err)
   }


   // The secret data is stored as a base64-encoded JSON string in the "ipSec" key.
   dataB64, exists := sec.Data["ipSec"]
   if !exists {
       t.Fatalf("secret %q does not contain key 'ipSec'", secretName)
   }
   // In Kubernetes, secret.Data fields are []byte already decoded from base64.
   // In this case, the underlying code marshals the IpSecKey via json.Marshal,
   // so dataB64 is the JSON bytes.
   var ipSecKey IpSecKey
   err = json.Unmarshal(dataB64, &ipSecKey)
   if err != nil {
       t.Fatalf("failed to unmarshal secret data: %v", err)
   }
   t.Logf("Created secret with SPI: %d", ipSecKey.Spi)
   if ipSecKey.Spi != 1 {
       t.Errorf("Expected SPI to be 1 on creation, got %d", ipSecKey.Spi)
   }


   // Step 3: Update the secret by running the command again with a new key.
   key2, err := generateRandomKey()
   if err != nil {
       t.Fatalf("failed to generate second random key: %v", err)
   }
   t.Logf("Generated key2: %s", key2)
   cmd = exec.Command("kmeshctl", "secret", "--key", key2)
   output, err = cmd.CombinedOutput()
   if err != nil {
       t.Fatalf("failed to run kmeshctl secret command for update: %v, output: %s", err, string(output))
   }
   t.Logf("Output of second 'kmeshctl secret' command: %s", string(output))


   // Step 4: Wait for the secret to be updated.
   secUpdated, err := waitForSecret(secretName, namespace, 30*time.Second)
   if err != nil {
       t.Fatalf("failed to get updated secret: %v", err)
   }
   dataB64 = secUpdated.Data["ipSec"]
   var ipSecKeyUpdated IpSecKey
   err = json.Unmarshal(dataB64, &ipSecKeyUpdated)
   if err != nil {
       t.Fatalf("failed to unmarshal updated secret data: %v", err)
   }
   t.Logf("Updated secret with SPI: %d", ipSecKeyUpdated.Spi)
   expectedSPI := ipSecKey.Spi + 1
   if ipSecKeyUpdated.Spi != expectedSPI {
       t.Errorf("Expected updated SPI to be %d, but got %d", expectedSPI, ipSecKeyUpdated.Spi)
   }
}


