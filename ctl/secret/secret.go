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

	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Use secrets to manage secret configuration data for IPsec",
		Example: `# Use kmeshctl secret to manage secret configuration data for IPsec:
kmeshctl secret create or kmeshctl secret create --key=$(echo -n "{36-character user-defined key here}" | xxd -p -c 64)
kmeshctl secret get
kmeshctl secret delete
`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
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
		RunE: func(cmd *cobra.Command, args []string) error {
			return CreateOrUpdateSecret(cmd, args)
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
		RunE: func(cmd *cobra.Command, args []string) error {
			return GetSecret(cmd)
		},
	}

	// delete cmd
	deleteCmd := &cobra.Command{
		Use:     "delete",
		Short:   "Delete IPsec key and configuration by kmeshctl",
		Example: `kmeshctl secret delete`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return DeleteSecret()
		},
	}

	// add sub-command
	cmd.AddCommand(createCmd)
	cmd.AddCommand(getCmd)
	cmd.AddCommand(deleteCmd)

	return cmd
}

func createKubeClient() (kube.CLIClient, error) {
	clientset, err := utils.CreateKubeClient()
	if err != nil {
		return nil, fmt.Errorf("failed to connect k8s client, %v", err)
	}
	return clientset, nil
}

func CreateOrUpdateSecret(cmd *cobra.Command, args []string) error {
	var err error
	clientset, err = createKubeClient()
	if err != nil {
		return err
	}
	var ipSecKey, ipSecKeyOld encryption.IpSecKey

	ipSecKey.AeadKeyName = AeadAlgoName

	aeadKeyArg, _ := cmd.Flags().GetString("key")

	var aeadKey []byte

	if !cmd.Flags().Changed("key") {
		aeadKey = make([]byte, AeadKeyLength)
		_, err := rand.Read(aeadKey)
		if err != nil {
			return fmt.Errorf("failed to generate random key: %v", err)
		}
	} else {
		aeadKey, err = hex.DecodeString(aeadKeyArg)
		if err != nil {
			return fmt.Errorf("failed to decode hex string: %v, input: %v", err, aeadKeyArg)
		}
	}

	if len(aeadKey) != AeadKeyLength {
		return fmt.Errorf("invalid key length: expected %d bytes, got %d bytes (key must be 256-bit + 32-bit salt)", AeadKeyLength, len(aeadKey))
	}

	ipSecKey.AeadKey = aeadKey

	ipSecKey.Length = AeadAlgoICVLength

	secretOld, err := clientset.Kube().CoreV1().Secrets(utils.KmeshNamespace).Get(context.TODO(), SecretName, metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to get secret: %v, %v", SecretName, err)
		}
		ipSecKey.Spi = 1
	} else {
		err = json.Unmarshal(secretOld.Data["ipSec"], &ipSecKeyOld)
		if err != nil {
			return fmt.Errorf("failed to unmarshal secret: %v, %v", secretOld, err)
		}
		ipSecKey.Spi = ipSecKeyOld.Spi + 1
	}

	secretData, err := json.Marshal(ipSecKey)
	if err != nil {
		return fmt.Errorf("failed to convert ipsec key to secret data, %v", err)
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
			return fmt.Errorf("failed to create %v secret, %v", SecretName, err)
		}
	} else {
		_, err = clientset.Kube().CoreV1().Secrets(utils.KmeshNamespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update %v secret, %v", SecretName, err)
		}
	}
	return nil
}

func GetSecret(cmd *cobra.Command) error {
	var err error
	clientset, err = createKubeClient()
	if err != nil {
		return err
	}
	secret, err := clientset.Kube().CoreV1().Secrets(utils.KmeshNamespace).Get(context.TODO(), SecretName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("secret %s not found", SecretName)
		}
		return fmt.Errorf("failed to get secret: %v", err)
	}

	if secret.Data == nil || secret.Data["ipSec"] == nil {
		return fmt.Errorf("invalid secret data: missing ipSec field")
	}

	// Parse the IPsec data
	var ipSecKey encryption.IpSecKey
	if err := json.Unmarshal(secret.Data["ipSec"], &ipSecKey); err != nil {
		return fmt.Errorf("failed to unmarshal secret data: %v", err)
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
		return fmt.Errorf("failed to marshal display data: %v", err)
	}

	cmd.Printf("Secret name: %s\n", SecretName)
	cmd.Printf("Namespace: %s\n", utils.KmeshNamespace)
	cmd.Printf("Created: %s\n", secret.CreationTimestamp.Format("2006-01-02 15:04:05"))
	cmd.Println("IPsec Configuration:")
	cmd.Println(string(displayData))
	return nil
}

func DeleteSecret() error {
	var err error
	clientset, err = createKubeClient()
	if err != nil {
		return err
	}
	err = clientset.Kube().CoreV1().Secrets(utils.KmeshNamespace).Delete(context.TODO(), SecretName, metav1.DeleteOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("secret %s not found", SecretName)
		}
		return fmt.Errorf("failed to delete secret: %v", err)
	}
	return nil
}
