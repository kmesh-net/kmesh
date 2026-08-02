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

package security

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"
	"istio.io/istio/pkg/security"
	"istio.io/istio/pkg/test/util/retry"

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
	assert.NoError(t, err, "NewSecretManager failed %v", err)
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
	assert.NoError(t, err, "NewSecretManager failed %v", err)
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
		secretManager.certsCache.mu.RLock()
		cert2 := secretManager.certsCache.certs[identity1]
		if cert2 != nil && cert2.cert != nil && cert2.cert.CreatedTime != oldCert.CreatedTime {
			newCert = *cert2.cert
			secretManager.certsCache.mu.RUnlock()
			break
		}
		secretManager.certsCache.mu.RUnlock()
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
	assert.NoError(t, err, "NewSecretManager failed %v", err)

	var fail atomic.Bool
	fail.Store(true)
	patches2 := gomonkey.NewPatches()
	defer patches2.Reset()
	patches2.ApplyMethodFunc(secretManager.caClient, "FetchCert", func(identity string) (*security.SecretItem, error) {
		if fail.Load() {
			return nil, fmt.Errorf("abnormal test")
		}
		return &security.SecretItem{
			ResourceName: identity,
			ExpireTime:   time.Now().Add(24 * time.Hour),
		}, nil
	})

	go secretManager.Run(stopCh)
	identity := "identity"
	secretManager.SendCertRequest(identity, ADD)
	time.Sleep(100 * time.Millisecond)
	fail.Store(false)

	secretManager.SendCertRequest(identity, RETRY)

	err = retry.UntilSuccess(
		func() error {
			cert := secretManager.GetCert(identity)
			if cert != nil {
				secretManager.certsCache.mu.RLock()
				hasCert := cert.cert != nil
				secretManager.certsCache.mu.RUnlock()
				if hasCert {
					return nil
				}
			}
			return fmt.Errorf("cert not found for identity %s", identity)
		},
		retry.Delay(100*time.Millisecond),
		retry.Timeout(6*time.Second),
	)

	if err != nil {
		t.Errorf("Failed to fetch cert after retry: %v", err)
	}

	close(stopCh)
}

func TestBackoffWithJitter(t *testing.T) {
	t.Run("backoff increases exponentially", func(t *testing.T) {
		base := 200 * time.Millisecond
		max := 30 * time.Second
		var prev time.Duration
		for attempt := 0; attempt < 8; attempt++ {
			d := backoffWithJitter(attempt, base, max)
			if attempt > 0 {
				// Each delay should generally be larger than the previous one
				// (within jitter tolerance) until hitting the cap.
				assert.Greater(t, d, prev/3, "attempt %d delay should grow", attempt)
			}
			assert.LessOrEqual(t, d, max+max/4, "delay must not exceed max + jitter margin")
			prev = d
		}
	})

	t.Run("delay is capped at maxDelay", func(t *testing.T) {
		base := 100 * time.Millisecond
		max := 1 * time.Second
		for i := 0; i < 50; i++ {
			d := backoffWithJitter(20, base, max)
			// With 25% jitter, the max possible value is 1.25 * maxDelay.
			assert.LessOrEqual(t, d, time.Duration(float64(max)*1.25)+time.Millisecond)
		}
	})

	t.Run("jitter keeps delay within bounds", func(t *testing.T) {
		base := 1 * time.Second
		max := 30 * time.Second
		for i := 0; i < 100; i++ {
			// First attempt (nextAttempt=1) should return baseDelay
			d := backoffWithJitter(1, base, max)
			assert.GreaterOrEqual(t, d, time.Duration(float64(base)*0.75)-time.Millisecond)
			assert.LessOrEqual(t, d, time.Duration(float64(base)*1.25)+time.Millisecond)
		}
	})
}

func TestCertFetchGiveUp(t *testing.T) {
	patches := gomonkey.NewPatches()
	patches.ApplyFunc(newCaClient, func(opts *security.Options, tlsOpts *tlsOptions) (CaClient, error) {
		return camock.NewMockCaClient(opts, 2*time.Hour)
	})
	defer patches.Reset()

	stopCh := make(chan struct{})
	secretManager, err := NewSecretManager()
	assert.NoError(t, err, "NewSecretManager failed %v", err)

	// Mock FetchCert to always fail
	patches2 := gomonkey.NewPatches()
	defer patches2.Reset()
	patches2.ApplyMethodFunc(secretManager.caClient, "FetchCert", func(identity string) (*security.SecretItem, error) {
		return nil, fmt.Errorf("persistent CA failure")
	})

	// Speed up the test by reducing delays
	patches.ApplyGlobalVar(&certFetchBaseDelay, 10*time.Millisecond)
	patches.ApplyGlobalVar(&certFetchMaxDelay, 50*time.Millisecond)
	patches.ApplyGlobalVar(&certFetchMaxRetries, 3)

	go secretManager.Run(stopCh)
	identity := "give-up-identity"
	secretManager.SendCertRequest(identity, ADD)

	// Wait for the retry limit to be reached.
	// 3 retries + 1 initial = 4 attempts total?
	// nextAttempt > certFetchMaxRetries (3).
	// nextAttempt starts at 1, 2, 3, 4. When it's 4, 4 > 3, it gives up.
	retry.UntilSuccess(
		func() error {
			secretManager.certRetryMu.Lock()
			attempts := secretManager.certRetryAttempts[identity]
			secretManager.certRetryMu.Unlock()
			if attempts == 0 { // attempts should be deleted on give up
				return nil
			}
			return fmt.Errorf("still retrying, attempts=%d", attempts)
		},
		retry.Delay(100*time.Millisecond),
		retry.Timeout(2*time.Second),
	)

	assert.Equal(t, int64(4), secretManager.certFetchRetries.Load(), "should have attempted 4 times total before giving up")
	close(stopCh)
}

func TestCertFetchRetriesMetric(t *testing.T) {
	patches := gomonkey.NewPatches()
	patches.ApplyFunc(newCaClient, func(opts *security.Options, tlsOpts *tlsOptions) (CaClient, error) {
		return camock.NewMockCaClient(opts, 2*time.Hour)
	})
	defer patches.Reset()

	stopCh := make(chan struct{})
	secretManager, err := NewSecretManager()
	assert.NoError(t, err, "NewSecretManager failed %v", err)

	var failCount atomic.Int32
	patches2 := gomonkey.NewPatches()
	defer patches2.Reset()
	patches2.ApplyMethodFunc(secretManager.caClient, "FetchCert", func(identity string) (*security.SecretItem, error) {
		count := failCount.Add(1)
		if count <= 2 {
			return nil, fmt.Errorf("simulated CA failure %d", count)
		}
		return &security.SecretItem{
			ResourceName: identity,
			ExpireTime:   time.Now().Add(24 * time.Hour),
		}, nil
	})

	go secretManager.Run(stopCh)
	identity := "metric-test-identity"
	secretManager.SendCertRequest(identity, ADD)

	err = retry.UntilSuccess(
		func() error {
			cert := secretManager.GetCert(identity)
			if cert != nil {
				secretManager.certsCache.mu.RLock()
				hasCert := cert.cert != nil
				secretManager.certsCache.mu.RUnlock()
				if hasCert {
					return nil
				}
			}
			return fmt.Errorf("cert not found for identity %s", identity)
		},
		retry.Delay(200*time.Millisecond),
		retry.Timeout(10*time.Second),
	)
	assert.NoError(t, err, "cert should eventually be fetched after retries")

	retries := secretManager.CertFetchRetries()
	assert.Greater(t, retries, int64(0), "retry counter should have been incremented")

	close(stopCh)
}
