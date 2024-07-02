/*
 * Copyright 2024 The Kmesh Authors.
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

package security

import (
	"fmt"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"

	"istio.io/istio/pkg/security"

	camock "kmesh.net/kmesh/pkg/controller/security/mock"
)

func (s *SecretManager) GetCert(identity string) *certItem {
	s.certsCache.mu.RLock()
	defer s.certsCache.mu.RUnlock()
	certificate := s.certsCache.certs[identity]
	return certificate
}

func TestSecurity(t *testing.T) {
	t.Run("TestBaseCert", func(t *testing.T) {
		runTestBaseCert(t)
	})
	t.Run("TestCertRotate", func(t *testing.T) {
		runTestCertRotate(t)
	})
	t.Run("TestretryFetchCert", func(t *testing.T) {
		runTestretryFetchCert(t)
	})
}

// Test certificate add/delete
func runTestBaseCert(t *testing.T) {
	patches := gomonkey.NewPatches()
	patches.ApplyFunc(newCaClient, func(opts *security.Options, tlsOpts *tlsOptions) (CaClient, error) {
		return camock.NewMockCaClient(opts, 2*time.Hour)
	})
	defer patches.Reset()

	stopCh := make(chan struct{})
	secretManager, err := NewSecretManager()
	assert.ErrorIsf(t, err, nil, "NewSecretManager failed %v", err)
	go secretManager.Run(stopCh)

	identity1 := "identity1"
	identity2 := "identity2"

	// Add multiple times, check refCnt is added and accumulation
	secretManager.SendCertRequest(identity1, ADD)
	secretManager.SendCertRequest(identity1, ADD)
	secretManager.SendCertRequest(identity2, ADD)
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int32(2), secretManager.GetCert(identity1).refCnt)
	assert.Equal(t, int32(1), secretManager.GetCert(identity2).refCnt)

	// delete, check refCnt delete and subtraction
	secretManager.SendCertRequest(identity1, DELETE)
	secretManager.SendCertRequest(identity2, DELETE)
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int32(1), secretManager.GetCert(identity1).refCnt)
	assert.Nil(t, secretManager.GetCert(identity2))

	secretManager.SendCertRequest(identity1, DELETE)
	time.Sleep(100 * time.Millisecond)
	assert.Nil(t, secretManager.GetCert(identity1))
	close(stopCh)
}

// Test certificate auto-refresh queue
func runTestCertRotate(t *testing.T) {
	patches := gomonkey.NewPatches()
	patches.ApplyFunc(newCaClient, func(opts *security.Options, tlsOpts *tlsOptions) (CaClient, error) {
		// One-hour validity period, it will be Rotated after 2 second.
		return camock.NewMockCaClient(opts, 1*time.Hour+2*time.Second)
	})
	defer patches.Reset()

	stopCh := make(chan struct{})
	secretManager, err := NewSecretManager()
	assert.ErrorIsf(t, err, nil, "NewSecretManager failed %v", err)
	go secretManager.Run(stopCh)

	identity1 := "identity1"
	identity2 := "identity2"

	secretManager.SendCertRequest(identity1, ADD)
	secretManager.SendCertRequest(identity2, Rotate)

	var oldCert security.SecretItem
	var newCert security.SecretItem
	for {
		cert1 := secretManager.GetCert(identity1)
		if cert1 != nil {
			secretManager.certsCache.mu.RLock()
			if cert1.cert != nil {
				oldCert = *cert1.cert
			}
			secretManager.certsCache.mu.RUnlock()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// wait for rotate cert
	time.Sleep(2 * time.Second)
	for {
		cert2 := secretManager.GetCert(identity1)
		if cert2 != nil && cert2.cert.CreatedTime != oldCert.CreatedTime {
			secretManager.certsCache.mu.RLock()
			newCert = *cert2.cert
			secretManager.certsCache.mu.RUnlock()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// check if the cert rotated
	assert.NotEqual(t, oldCert.CertificateChain, newCert.CertificateChain)

	secretManager.SendCertRequest(identity1, DELETE)
	secretManager.SendCertRequest(identity2, DELETE)
	close(stopCh)
}

// Test certificate retryFetchCert
func runTestretryFetchCert(t *testing.T) {
	patches1 := gomonkey.NewPatches()
	patches1.ApplyFunc(newCaClient, func(opts *security.Options, tlsOpts *tlsOptions) (CaClient, error) {
		return camock.NewMockCaClient(opts, 2*time.Hour)
	})
	defer patches1.Reset()

	stopCh := make(chan struct{})
	secretManager, err := NewSecretManager()
	assert.ErrorIsf(t, err, nil, "NewSecretManager failed %v", err)

	patches2 := gomonkey.NewPatches()
	patches2.ApplyMethodFunc(secretManager.caClient, "FetchCert", func(identity string) (*security.SecretItem, error) {
		return nil, fmt.Errorf("abnormal test")
	})

	go secretManager.Run(stopCh)
	identity := "identity"
	identity1 := "identity1"
	secretManager.SendCertRequest(identity, ADD)
	time.Sleep(100 * time.Millisecond)
	patches2.Reset()
	secretManager.SendCertRequest(identity1, RETRY)
	time.Sleep(2000 * time.Millisecond)
	assert.NotNil(t, secretManager.GetCert(identity).cert)

	close(stopCh)
}
