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
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"

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
		Short: "Use secrets to generate secret configuration data for IPsec",
		Example: `# Use secrets to generate secret configuration data for IPsec:
 kmeshctl secret --key or -k, only support use aead algo: rfc4106(gcm(aes))
 key need 36 characters(use 32 characters as key, 4 characters as salt).
 Hexadecimal dump is required when the key is entered.
 e.g.:kmeshctl secret --key=$(dd if=/dev/urandom count=36 bs=1 2>/dev/null | xxd -p -c 64)
 e.g.:kmeshctl secret -k=$(echo -n "{36-character user-defined key here}" | xxd -p -c 64)`,
		Args: cobra.MaximumNArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			GeneralSecret(cmd, args)
		},
	}
	cmd.Flags().StringP("key", "k", "", "key of the encryption")
	return cmd
}

func GeneralSecret(cmd *cobra.Command, args []string) {
	var ipSecKey, ipSecKeyOld ipsec.IpSecKey
	var err error

	clientset, err := utils.CreateKubeClient()
	if err != nil {
		log.Errorf("failed to connect k8s client, %v", err)
		os.Exit(1)
	}

	ipSecKey.AeadKeyName = AeadAlgoName

	aeadKeyArg, _ := cmd.Flags().GetString("key")

	if strings.Compare(aeadKeyArg, "") == 0 {
		log.Errorf("no param --key or -k, we need a encryption key")
		os.Exit(1)
	}

	aeadKey, err := hex.DecodeString(aeadKeyArg)
	if err != nil {
		log.Errorf("invalid input argument, %v, input: %v", err, aeadKeyArg)
		os.Exit(1)
	}

	if len(aeadKey) != 36 {
		log.Errorf("The key length is not enough!. It requires 36 characters(256-bit key + 32-bit salt)")
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
