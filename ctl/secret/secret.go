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
	"io"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/controller/encryption"
	"kmesh.net/kmesh/pkg/kube"
)

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
			return cmd.Help()
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
			cli, err := utils.CreateKubeClient()
			if err != nil {
				return fmt.Errorf("failed to connect k8s client: %w", err)
			}
			return GetSecret(cli, cmd.OutOrStdout())
		},
	}

	// delete cmd
	deleteCmd := &cobra.Command{
		Use:     "delete",
		Short:   "Delete IPsec key and configuration by kmeshctl",
		Example: `kmeshctl secret delete`,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := utils.CreateKubeClient()
			if err != nil {
				return fmt.Errorf("failed to connect k8s client: %w", err)
			}
			return DeleteSecret(cli)
		},
	}

	// add sub-command
	cmd.AddCommand(createCmd)
	cmd.AddCommand(getCmd)
	cmd.AddCommand(deleteCmd)

	return cmd
}

func CreateOrUpdateSecret(cmd *cobra.Command, args []string) error {
	clientset, err := utils.CreateKubeClient()
	if err != nil {
		return fmt.Errorf("failed to connect k8s client: %w", err)
	}

	var ipSecKey, ipSecKeyOld encryption.IpSecKey

	ipSecKey.AeadKeyName = AeadAlgoName

	aeadKeyArg, _ := cmd.Flags().GetString("key")

	var aeadKey []byte

	if !cmd.Flags().Changed("key") {
		aeadKey = make([]byte, AeadKeyLength)
		if _, err := rand.Read(aeadKey); err != nil {
			return fmt.Errorf("failed to generate random key: %w", err)
		}
	} else {
		aeadKey, err = hex.DecodeString(aeadKeyArg)
		if err != nil {
			return fmt.Errorf("failed to decode hex string: %w, input: %v", err, aeadKeyArg)
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
			return fmt.Errorf("failed to get secret %v: %w", SecretName, err)
		}
		ipSecKey.Spi = 1
	} else {
		if err := json.Unmarshal(secretOld.Data["ipSec"], &ipSecKeyOld); err != nil {
			return fmt.Errorf("failed to unmarshal secret: %w", err)
		}
		ipSecKey.Spi = ipSecKeyOld.Spi + 1
	}

	secretData, err := json.Marshal(ipSecKey)
	if err != nil {
		return fmt.Errorf("failed to convert ipsec key to secret data: %w", err)
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
		if _, err = clientset.Kube().CoreV1().Secrets(utils.KmeshNamespace).Create(context.TODO(), secret, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("failed to create %v secret: %w", SecretName, err)
		}
	} else {
		if _, err = clientset.Kube().CoreV1().Secrets(utils.KmeshNamespace).Update(context.TODO(), secret, metav1.UpdateOptions{}); err != nil {
			return fmt.Errorf("failed to update %v secret: %w", SecretName, err)
		}
	}
	return nil
}

func GetSecret(clientset kube.CLIClient, out io.Writer) error {
	secret, err := clientset.Kube().CoreV1().Secrets(utils.KmeshNamespace).Get(context.TODO(), SecretName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("secret %s not found", SecretName)
		}
		return fmt.Errorf("failed to get secret: %w", err)
	}

	if secret.Data == nil || secret.Data["ipSec"] == nil {
		return fmt.Errorf("invalid secret data: missing ipSec field")
	}

	var ipSecKey encryption.IpSecKey
	if err := json.Unmarshal(secret.Data["ipSec"], &ipSecKey); err != nil {
		return fmt.Errorf("failed to unmarshal secret data: %w", err)
	}

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
		return fmt.Errorf("failed to marshal display data: %w", err)
	}

	fmt.Fprintf(out, "Secret name: %s\n", SecretName)
	fmt.Fprintf(out, "Namespace: %s\n", utils.KmeshNamespace)
	fmt.Fprintf(out, "Created: %s\n", secret.CreationTimestamp.Format("2006-01-02 15:04:05"))
	fmt.Fprintln(out, "IPsec Configuration:")
	fmt.Fprintln(out, string(displayData))
	return nil
}

func DeleteSecret(clientset kube.CLIClient) error {
	err := clientset.Kube().CoreV1().Secrets(utils.KmeshNamespace).Delete(context.TODO(), SecretName, metav1.DeleteOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("secret %s not found", SecretName)
		}
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	return nil
}
