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

package secret

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/controller/encryption/ipsec"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerScope("kmeshctl/secret")

const (
	SecretName        = "kmesh-ipsec"
	AeadAlgoName      = "rfc4106(gcm(aes))"
	AeadAlgoICVLength = 128 // IPsec support ICV length can use 64/96/128 bit when use gcm-aes, we use 128 bit
	AeadKeyLength     = 36  // aead algo use rfc4106(gcm(aes)). use 32 char(256 bit) as the key and 4 char (32bit) as the salt value
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage IPsec secrets for Kmesh",
		Long:  "Generate and manage IPsec encryption secrets for secure communication between nodes",
	}

	cmd.AddCommand(newCreateCmd())

	return cmd
}

func newCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new IPsec secret with automatically generated key",
		Long: `Create a new IPsec secret with automatically generated encryption key.
The key is generated using cryptographically secure random bytes and formatted
for use with the rfc4106(gcm(aes)) AEAD algorithm.`,
		Example: `# Create a new IPsec secret with automatically generated key:
kmeshctl secret create

# This will generate a 36-byte key (32-byte key + 4-byte salt) and create
# the 'kmesh-ipsec' secret in the kmesh-system namespace.`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			createSecretWithRandomKey()
		},
	}
	return cmd
}

// generateRandomKey generates a cryptographically secure random key for IPsec
func generateRandomKey() ([]byte, error) {
	key := make([]byte, AeadKeyLength)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random key: %v", err)
	}
	return key, nil
}

func createSecretWithRandomKey() {
	var ipSecKey, ipSecKeyOld ipsec.IpSecKey
	var err error

	clientset, err := utils.CreateKubeClient()
	if err != nil {
		log.Errorf("failed to connect k8s client, %v", err)
		os.Exit(1)
	}

	ipSecKey.AeadKeyName = AeadAlgoName

	// Generate random key automatically
	aeadKey, err := generateRandomKey()
	if err != nil {
		log.Errorf("failed to generate random key: %v", err)
		os.Exit(1)
	}

	ipSecKey.AeadKey = aeadKey
	ipSecKey.Length = AeadAlgoICVLength

	secretOld, err := clientset.Kube().CoreV1().Secrets(utils.KmeshNamespace).Get(context.TODO(), SecretName, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			log.Errorf("failed to get secret: %v, %v", SecretName, err)
			os.Exit(1)
		}
		ipSecKey.Spi = 1
	} else {
		err = json.Unmarshal(secretOld.Data["ipSec"], &ipSecKeyOld)
		if err != nil {
			log.Errorf("failed to unmarshal secret: %v, %v", secretOld, err)
			os.Exit(1)
		}
		ipSecKey.Spi = ipSecKeyOld.Spi + 1
	}

	secretData, err := json.Marshal(ipSecKey)
	if err != nil {
		log.Errorf("failed to convert ipsec key to secret data, %v", err)
		os.Exit(1)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: SecretName,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"ipSec": []byte(secretData),
		},
	}

	if ipSecKey.Spi == 1 {
		_, err = clientset.Kube().CoreV1().Secrets(utils.KmeshNamespace).Create(context.TODO(), secret, metav1.CreateOptions{})
		if err != nil {
			log.Errorf("failed to create %v secret, %v", SecretName, err)
			os.Exit(1)
		}
	} else {
		_, err = clientset.Kube().CoreV1().Secrets(utils.KmeshNamespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
		if err != nil {
			log.Errorf("failed to update %v secret, %v", SecretName, err)
			os.Exit(1)
		}
	}
}
