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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/controller/encryption"
	"kmesh.net/kmesh/pkg/kube"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerScope("kmeshctl/secret")
var clientset kube.CLIClient

const (
	SecretName        = "kmesh-ipsec"
	AeadAlgoName      = "rfc4106(gcm(aes))"
	AeadAlgoICVLength = 128 // IPsec support ICV length can use 64/96/128 bit when use gcm-aes, we use 128 bit
	AeadKeyLength     = 36  // aead algo use rfc4106(gcm(aes)). use 32 char(256 bit) as the key and 4 char (32bit) as the salt value
)

func NewCmd() *cobra.Command {
	clientset = createKubeClientOrExit()

	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Use secrets to manage secret configuration data for IPsec",
		Example: `# Use kmeshctl secret to manage secret configuration data for IPsec:
kmeshctl secret create or kmeshctl secret create --key=$(echo -n "{36-character user-defined key here}" | xxd -p -c 64)
kmeshctl secret get
kmeshctl secret delete
`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
		},
	}

	// create cmd
	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Generate IPsec key and configuration by kmeshctl",
		Example: `# Generate IPsec configuration with random IPsec key:
kmeshctl secret create
# Generate IPsec configuration with user-defined key:
kmeshctl secret create --key=$(echo -n "{36-character user-defined key here}" | xxd -p -c 64)`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			CreateOrUpdateSecret(cmd, args)
		},
	}

	createCmd.Flags().StringP("key", "k", "", "key of the encryption") // user defined key

	// get cmd
	getCmd := &cobra.Command{
		Use:   "get",
		Short: "Get IPsec key and configuration by kmeshctl",
		Example: `# Get IPsec key and configuration by kmeshctl. The results will be displayed in JSON format.
kmeshctl secret get`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			GetSecret()
		},
	}

	// delete cmd
	deleteCmd := &cobra.Command{
		Use:     "delete",
		Short:   "Delete IPsec key and configuration by kmeshctl",
		Example: `kmeshctl secret delete`,
		Args:    cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			DeleteSecret()
		},
	}

	// add sub-command
	cmd.AddCommand(createCmd)
	cmd.AddCommand(getCmd)
	cmd.AddCommand(deleteCmd)

	return cmd
}

func createKubeClientOrExit() kube.CLIClient {
	clientset, err := utils.CreateKubeClient()
	if err != nil {
		log.Errorf("failed to connect k8s client, %v", err)
		os.Exit(1)
	}
	return clientset
}

func CreateOrUpdateSecret(cmd *cobra.Command, args []string) {
	var ipSecKey, ipSecKeyOld encryption.IpSecKey
	var err error

	ipSecKey.AeadKeyName = AeadAlgoName

	aeadKeyArg, _ := cmd.Flags().GetString("key")

	var aeadKey []byte

	if !cmd.Flags().Changed("key") {
		aeadKey = make([]byte, AeadKeyLength)
		_, err := rand.Read(aeadKey)
		if err != nil {
			log.Errorf("failed to generate random key: %v", err)
			os.Exit(1)
		}
	} else {
		aeadKey, err = hex.DecodeString(aeadKeyArg)
		if err != nil {
			log.Errorf("failed to decode hex string: %v, input: %v", err, aeadKeyArg)
			os.Exit(1)
		}
	}

	if len(aeadKey) != AeadKeyLength {
		log.Errorf("invalid key length: expected %d bytes, got %d bytes (key must be 256-bit + 32-bit salt)", AeadKeyLength, len(aeadKey))
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

func GetSecret() {
	secret, err := clientset.Kube().CoreV1().Secrets(utils.KmeshNamespace).Get(context.TODO(), SecretName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Errorf("secret %s not found", SecretName)
			os.Exit(1)
		}
		log.Errorf("failed to get secret: %v", err)
		os.Exit(1)
	}

	if secret.Data == nil || secret.Data["ipSec"] == nil {
		log.Errorf("invalid secret data: missing ipSec field")
		os.Exit(1)
	}

	// Parse the IPsec data
	var ipSecKey encryption.IpSecKey
	if err := json.Unmarshal(secret.Data["ipSec"], &ipSecKey); err != nil {
		log.Errorf("failed to unmarshal secret data: %v", err)
		os.Exit(1)
	}

	// Create a display structure with hex string key
	displayKey := struct {
		Spi         int    `json:"spi"`
		AeadKeyName string `json:"aeadKeyName"`
		AeadKey     string `json:"aeadKey"`
		Length      int    `json:"length"`
	}{
		Spi:         ipSecKey.Spi,
		AeadKeyName: ipSecKey.AeadKeyName,
		AeadKey:     hex.EncodeToString(ipSecKey.AeadKey),
		Length:      ipSecKey.Length,
	}

	displayData, err := json.MarshalIndent(displayKey, "", "  ")
	if err != nil {
		log.Errorf("failed to marshal display data: %v", err)
		os.Exit(1)
	}

	fmt.Printf("Secret name: %s\n", SecretName)
	fmt.Printf("Namespace: %s\n", utils.KmeshNamespace)
	fmt.Printf("Created: %s\n", secret.CreationTimestamp.Format("2006-01-02 15:04:05"))
	fmt.Println("IPsec Configuration:")
	fmt.Println(string(displayData))
}

func DeleteSecret() {
	err := clientset.Kube().CoreV1().Secrets(utils.KmeshNamespace).Delete(context.TODO(), SecretName, metav1.DeleteOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Errorf("secret %s not found", SecretName)
			os.Exit(1)
		}
		log.Errorf("failed to delete secret: %v", err)
		os.Exit(1)
	}
}
