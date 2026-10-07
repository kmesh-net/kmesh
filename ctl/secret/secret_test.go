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
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	gatewayapiclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/controller/encryption"
	"kmesh.net/kmesh/pkg/kube"
)

type fakeCLIClient struct {
	kube kubernetes.Interface
}

func (f *fakeCLIClient) Kube() kubernetes.Interface {
	return f.kube
}

func (f *fakeCLIClient) GatewayAPI() gatewayapiclient.Interface {
	return nil
}

func (f *fakeCLIClient) PodsForSelector(ctx context.Context, namespace string, labelSelectors ...string) (*corev1.PodList, error) {
	return nil, nil
}

func (f *fakeCLIClient) NewPortForwarder(podName string, ns string, localAddress string, localPort int, podPort int) (kube.PortForwarder, error) {
	return nil, nil
}

func newTestCLIClient() *fakeCLIClient {
	return &fakeCLIClient{
		kube: fake.NewSimpleClientset(),
	}
}

func TestNewCmd(t *testing.T) {
	cmd := NewCmd()
	assert.NotNil(t, cmd)
	assert.Equal(t, "secret", cmd.Use)

	subCmds := cmd.Commands()
	subNames := make([]string, 0, len(subCmds))
	for _, c := range subCmds {
		subNames = append(subNames, c.Name())
	}
	assert.Contains(t, subNames, "create")
	assert.Contains(t, subNames, "get")
	assert.Contains(t, subNames, "delete")
}

func TestCreateOrUpdateSecret_DefaultRandomKey(t *testing.T) {
	fc := newTestCLIClient()
	setKubeClient(fc)
	defer setKubeClient(nil)

	cmd := &cobra.Command{}
	cmd.Flags().StringP("key", "k", "", "key of the encryption")

	err := CreateOrUpdateSecret(cmd, []string{})
	assert.NoError(t, err)

	sec, err := fc.Kube().CoreV1().Secrets(utils.KmeshNamespace).Get(context.TODO(), SecretName, metav1.GetOptions{})
	assert.NoError(t, err)
	assert.NotNil(t, sec)
	assert.Equal(t, SecretName, sec.Name)
	assert.Equal(t, corev1.SecretTypeOpaque, sec.Type)

	var ipSecKey encryption.IpSecKey
	err = json.Unmarshal(sec.Data["ipSec"], &ipSecKey)
	assert.NoError(t, err)
	assert.Equal(t, 1, ipSecKey.Spi)
	assert.Equal(t, AeadAlgoName, ipSecKey.AeadKeyName)
	assert.Equal(t, AeadAlgoICVLength, ipSecKey.Length)
	assert.Equal(t, AeadKeyLength, len(ipSecKey.AeadKey))
}

func TestCreateOrUpdateSecret_ExistingSecretUpdatesSPI(t *testing.T) {
	fc := newTestCLIClient()
	setKubeClient(fc)
	defer setKubeClient(nil)

	cmd := &cobra.Command{}
	cmd.Flags().StringP("key", "k", "", "key of the encryption")

	// First creation: SPI should be 1
	err := CreateOrUpdateSecret(cmd, []string{})
	assert.NoError(t, err)

	// Second creation: SPI should be incremented to 2
	err = CreateOrUpdateSecret(cmd, []string{})
	assert.NoError(t, err)

	sec, err := fc.Kube().CoreV1().Secrets(utils.KmeshNamespace).Get(context.TODO(), SecretName, metav1.GetOptions{})
	assert.NoError(t, err)

	var ipSecKey encryption.IpSecKey
	err = json.Unmarshal(sec.Data["ipSec"], &ipSecKey)
	assert.NoError(t, err)
	assert.Equal(t, 2, ipSecKey.Spi)
}

func TestCreateOrUpdateSecret_CustomKey(t *testing.T) {
	fc := newTestCLIClient()
	setKubeClient(fc)
	defer setKubeClient(nil)

	expectedKey := make([]byte, AeadKeyLength)
	for i := range expectedKey {
		expectedKey[i] = byte(i)
	}
	hexKey := hex.EncodeToString(expectedKey)

	cmd := &cobra.Command{}
	cmd.Flags().StringP("key", "k", "", "key of the encryption")
	assert.NoError(t, cmd.Flags().Set("key", hexKey))

	err := CreateOrUpdateSecret(cmd, []string{})
	assert.NoError(t, err)

	sec, err := fc.Kube().CoreV1().Secrets(utils.KmeshNamespace).Get(context.TODO(), SecretName, metav1.GetOptions{})
	assert.NoError(t, err)

	var ipSecKey encryption.IpSecKey
	err = json.Unmarshal(sec.Data["ipSec"], &ipSecKey)
	assert.NoError(t, err)
	assert.Equal(t, expectedKey, ipSecKey.AeadKey)
}

func TestCreateOrUpdateSecret_InvalidHexKey(t *testing.T) {
	fc := newTestCLIClient()
	setKubeClient(fc)
	defer setKubeClient(nil)

	cmd := &cobra.Command{}
	cmd.Flags().StringP("key", "k", "", "key of the encryption")
	assert.NoError(t, cmd.Flags().Set("key", "not-a-valid-hex-string!"))

	err := CreateOrUpdateSecret(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode hex string")
}

func TestCreateOrUpdateSecret_InvalidKeyLength(t *testing.T) {
	fc := newTestCLIClient()
	setKubeClient(fc)
	defer setKubeClient(nil)

	shortKey := hex.EncodeToString([]byte("too-short"))
	cmd := &cobra.Command{}
	cmd.Flags().StringP("key", "k", "", "key of the encryption")
	assert.NoError(t, cmd.Flags().Set("key", shortKey))

	err := CreateOrUpdateSecret(cmd, []string{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key length")
}

func TestGetSecret_Success(t *testing.T) {
	fc := newTestCLIClient()
	setKubeClient(fc)
	defer setKubeClient(nil)

	ipSecKey := encryption.IpSecKey{
		Spi:         1,
		AeadKeyName: AeadAlgoName,
		AeadKey:     make([]byte, AeadKeyLength),
		Length:      AeadAlgoICVLength,
	}
	data, err := json.Marshal(ipSecKey)
	assert.NoError(t, err)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: SecretName,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"ipSec": data,
		},
	}
	_, err = fc.Kube().CoreV1().Secrets(utils.KmeshNamespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	assert.NoError(t, err)

	err = GetSecret()
	assert.NoError(t, err)
}

func TestGetSecret_NotFound(t *testing.T) {
	fc := newTestCLIClient()
	setKubeClient(fc)
	defer setKubeClient(nil)

	err := GetSecret()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGetSecret_MissingIPSecField(t *testing.T) {
	fc := newTestCLIClient()
	setKubeClient(fc)
	defer setKubeClient(nil)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: SecretName,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{},
	}
	_, err := fc.Kube().CoreV1().Secrets(utils.KmeshNamespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	assert.NoError(t, err)

	err = GetSecret()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing ipSec field")
}

func TestGetSecret_InvalidJSON(t *testing.T) {
	fc := newTestCLIClient()
	setKubeClient(fc)
	defer setKubeClient(nil)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: SecretName,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"ipSec": []byte("invalid-json"),
		},
	}
	_, err := fc.Kube().CoreV1().Secrets(utils.KmeshNamespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	assert.NoError(t, err)

	err = GetSecret()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal secret data")
}

func TestDeleteSecret_Success(t *testing.T) {
	fc := newTestCLIClient()
	setKubeClient(fc)
	defer setKubeClient(nil)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: SecretName,
		},
		Type: corev1.SecretTypeOpaque,
	}
	_, err := fc.Kube().CoreV1().Secrets(utils.KmeshNamespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	assert.NoError(t, err)

	err = DeleteSecret()
	assert.NoError(t, err)

	_, err = fc.Kube().CoreV1().Secrets(utils.KmeshNamespace).Get(context.TODO(), SecretName, metav1.GetOptions{})
	assert.Error(t, err)
}

func TestDeleteSecret_NotFound(t *testing.T) {
	fc := newTestCLIClient()
	setKubeClient(fc)
	defer setKubeClient(nil)

	err := DeleteSecret()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
