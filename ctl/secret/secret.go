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
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/controller/encryption/ipsec"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerScope("kmeshctl/secret")

const (
	SecretName = "kmesh-ipsec"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Use secrets to generate secret configuration data for IPsec",
		Example: `# Use secrets to generate secret configuration data for IPsec:
 kmeshctl secret aeadAlgo aeadKey aeadLength`,
		Args: cobra.MinimumNArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			GeneralSecret(cmd, args)
		},
	}
	return cmd
}

func GeneralSecret(cmd *cobra.Command, args []string) {
	var ipSecKey, ipSecKeyOld ipsec.IpSecKey
	var err error

	/*
		spi, err := strconv.Atoi(args[0])
		if err != nil {
			log.Errorf("invalid input argument, %v, input spi is %v, we need a int8", err, args[0])
			os.Exit(1)
		}
		ipSecKey.Spi = int8(spi)
	*/

	clientset, err := utils.CreateKubeClient()
	if err != nil {
		log.Errorf("failed to connect k8s client, %v", err)
		os.Exit(1)
	}

	ipSecKey.AeadKeyName = args[0]
	if !strings.HasPrefix(ipSecKey.AeadKeyName, "rfc") {
		log.Errorf("invalid input argument, %v, spi keyalgo need begin with rfc, input: %v", err, args[0])
		os.Exit(1)
	}

	aeadKey, err := hex.DecodeString(args[1])
	if err != nil {
		log.Errorf("invalid input argument, %v, input: %v", err, args[1])
		os.Exit(1)
	}
	ipSecKey.AeadKey = aeadKey

	length, err := strconv.Atoi(args[2])
	if err != nil {
		log.Errorf("invalid input argument, %v, length can not parser, input: %v", err, args[2])
		os.Exit(1)
	}
	ipSecKey.Length = length

	ipSecKey.CreateTime = time.Now().Format("20060102150405")

	secretOld, err := clientset.Kube().CoreV1().Secrets(utils.KmeshNamespace).Get(context.TODO(), SecretName, metav1.GetOptions{})
	if err != nil {
		ipSecKey.Spi = 1
	} else {
		err = json.Unmarshal(secretOld.Data["keys"], &ipSecKeyOld)
		if err != nil {
			log.Errorf("failed to get secret %v, %v", SecretName, err)
			os.Exit(1)
		}
		if ipSecKeyOld.Spi == 15 {
			ipSecKey.Spi = 1
		} else {
			ipSecKey.Spi = ipSecKeyOld.Spi + 1
		}
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
			"keys": []byte(secretData),
		},
	}

	_, err = clientset.Kube().CoreV1().Secrets(utils.KmeshNamespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	if err == nil {
		return
	}
	_, err = clientset.Kube().CoreV1().Secrets(utils.KmeshNamespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
	if err != nil {
		log.Errorf("failed to update % secret, %v", SecretName, err)
		os.Exit(1)
	}

}
