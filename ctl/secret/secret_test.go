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
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/controller/encryption"
	"kmesh.net/kmesh/pkg/kube"
)

// fakeCLIClient only serves Kube(); the secret command does not use the other methods.
type fakeCLIClient struct {
	kube.CLIClient
	kubeClient kubernetes.Interface
}

func (f *fakeCLIClient) Kube() kubernetes.Interface {
	return f.kubeClient
}

func useFakeClient(t *testing.T, objs ...runtime.Object) *k8sfake.Clientset {
	t.Helper()
	fakeKube := k8sfake.NewSimpleClientset(objs...)
	oldClientset, oldClientInit := clientset, clientInit
	clientset, clientInit = &fakeCLIClient{kubeClient: fakeKube}, nil
	t.Cleanup(func() {
		clientset, clientInit = oldClientset, oldClientInit
	})
	return fakeKube
}

func newCreateCmd(t *testing.T) *cobra.Command {
	t.Helper()
	createCmd, _, err := NewCmd().Find([]string{"create"})
	require.NoError(t, err)
	return createCmd
}

func existingSecret(ipSec string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: SecretName, Namespace: utils.KmeshNamespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"ipSec": []byte(ipSec)},
	}
}

func storedIpSecKey(t *testing.T, fakeKube *k8sfake.Clientset) encryption.IpSecKey {
	t.Helper()
	secret, err := fakeKube.CoreV1().Secrets(utils.KmeshNamespace).Get(context.TODO(), SecretName, metav1.GetOptions{})
	require.NoError(t, err)
	var key encryption.IpSecKey
	require.NoError(t, json.Unmarshal(secret.Data["ipSec"], &key))
	return key
}

func TestCreateOrUpdateSecret(t *testing.T) {
	tests := []struct {
		name     string
		existing []runtime.Object
		wantVerb string
		wantSpi  int
	}{
		{
			name:     "no secret is created with spi 1",
			wantVerb: "create",
			wantSpi:  1,
		},
		{
			name:     "existing secret is rotated to the next spi",
			existing: []runtime.Object{existingSecret(`{"spi":1,"aeadKeyName":"rfc4106(gcm(aes))","length":128}`)},
			wantVerb: "update",
			wantSpi:  2,
		},
		{
			name:     "existing secret without spi is updated",
			existing: []runtime.Object{existingSecret(`{"aeadKeyName":"rfc4106(gcm(aes))","length":128}`)},
			wantVerb: "update",
			wantSpi:  1,
		},
		{
			name:     "existing secret with spi 0 is updated",
			existing: []runtime.Object{existingSecret(`{"spi":0,"aeadKeyName":"rfc4106(gcm(aes))","length":128}`)},
			wantVerb: "update",
			wantSpi:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeKube := useFakeClient(t, tt.existing...)

			require.NoError(t, CreateOrUpdateSecret(newCreateCmd(t), nil))

			actions := fakeKube.Actions()
			require.Len(t, actions, 2)
			assert.Equal(t, "get", actions[0].GetVerb())
			assert.Equal(t, tt.wantVerb, actions[1].GetVerb())

			key := storedIpSecKey(t, fakeKube)
			assert.Equal(t, tt.wantSpi, key.Spi)
			assert.Equal(t, AeadAlgoName, key.AeadKeyName)
			assert.Len(t, key.AeadKey, AeadKeyLength)
		})
	}
}

func TestCreateOrUpdateSecretWithUserKey(t *testing.T) {
	fakeKube := useFakeClient(t)
	userKey := make([]byte, AeadKeyLength)
	for i := range userKey {
		userKey[i] = byte(i)
	}
	createCmd := newCreateCmd(t)
	require.NoError(t, createCmd.Flags().Set("key", hex.EncodeToString(userKey)))

	require.NoError(t, CreateOrUpdateSecret(createCmd, nil))

	key := storedIpSecKey(t, fakeKube)
	assert.Equal(t, 1, key.Spi)
	assert.Equal(t, userKey, key.AeadKey)
}
