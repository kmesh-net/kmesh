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
	"sync"
	"time"

	istiosecurity "istio.io/istio/pkg/security"
	"k8s.io/client-go/util/workqueue"

	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerField("security")

type certItem struct {
	cert   *istiosecurity.SecretItem
	refCnt int32
}

type certsCache struct {
	certs map[string]*certItem
	mu    sync.RWMutex
}

type certRequest struct {
	Identity  string
	Operation int
}

type CaClient interface {
	CsrSend(csrPEM []byte, certValidsec int64, identity string) ([]string, error)
	FetchCert(identity string) (*istiosecurity.SecretItem, error)
	Close() error
}

type SecretManager struct {
	caClient CaClient

	// configOptions includes all configurable params for the cache.
	configOptions *istiosecurity.Options

	// storing certificates
	certsCache *certsCache

	// certs rotation priority queue based on exp
	certsRotateQueue workqueue.DelayingInterface

	certRequestChan chan certRequest
}

func (s *SecretManager) SendCertRequest(identity string, op int) {
	s.certRequestChan <- certRequest{Identity: identity, Operation: op}
}

func (s *SecretManager) handleCertRequests(stop <-chan struct{}) {
	for data := range s.certRequestChan {
		select {
		case <-stop:
			return
		default:
		}

		identity, op := data.Identity, data.Operation
		switch op {
		case ADD:
			certificate := s.certsCache.addOrUpdate(identity)
			if certificate != nil {
				log.Debugf("add identity: %v refCnt: %v", identity, certificate.refCnt)
				continue
			}
			// sign cert if only no cert exists for this identity
			go s.fetchCert(identity)
		case RETRY:
			s.retryFetchCert(identity)
		case DELETE:
			s.deleteCert(identity)
		case Rotate:
			s.rotateCert(identity)
		}
	}
}

func newCertCache() *certsCache {
	return &certsCache{
		certs: make(map[string]*certItem),
		mu:    sync.RWMutex{},
	}
}

func (s *SecretManager) StoreCert(identity string, newCert *istiosecurity.SecretItem) {
	s.certsCache.mu.Lock()
	defer s.certsCache.mu.Unlock()
	// Check if the key exists in the map
	existing := s.certsCache.certs[identity]
	if existing == nil {
		// This can happen when delete immediately happens after add
		log.Debugf("%v has been deleted", identity)
		return
	}
	// if the new cert expire time is before the existing one, it means the new cert is actually signed earlier,
	// just ignore it.
	if existing.cert != nil && newCert.ExpireTime.Before(existing.cert.ExpireTime) {
		return
	}

	existing.cert = newCert
	// push to rotate queue one hour before cert expire
	s.certsRotateQueue.AddAfter(identity, time.Until(newCert.ExpireTime.Add(-1*time.Hour)))
	log.Debugf("cert %v added to rotation queue, exp: %v", identity, newCert.ExpireTime)
}

// addOrUpdate checks whether the certificate already exists.
// If it exists, increment the reference count by 1,
// Otherwise, request a new certificate.
func (c *certsCache) addOrUpdate(identity string) *certItem {
	c.mu.Lock()
	defer c.mu.Unlock()
	cert := c.certs[identity]
	if cert != nil {
		cert.refCnt++
		return cert
	}
	cert = &certItem{
		refCnt: 1,
	}
	c.certs[identity] = cert
	return nil
}

// NewSecretManager creates a new secretManager
func NewSecretManager() (*SecretManager, error) {
	tlsOpts := &tlsOptions{
		RootCert: constants.RootCertPath,
	}

	options := NewSecurityOptions()
	caClient, err := newCaClient(options, tlsOpts)
	if err != nil {
		log.Errorf("err : %v", err)
		return nil, err
	}

	secretManager := SecretManager{
		caClient:         caClient,
		configOptions:    options,
		certsCache:       newCertCache(),
		certsRotateQueue: workqueue.NewDelayingQueue(),
		certRequestChan:  make(chan certRequest, maxConcurrentCSR),
	}
	return &secretManager, nil
}

func (s *SecretManager) Run(stop <-chan struct{}) {
	go s.handleCertRequests(stop)
	go s.rotateCerts()
	<-stop
	s.certsRotateQueue.ShutDown()
	s.caClient.Close()
}

// Automatically check and rotate when the validity period expires
func (s *SecretManager) rotateCerts() {
	for {
		element, quit := s.certsRotateQueue.Get()
		if quit {
			return
		}

		identity := element.(string)
		s.SendCertRequest(identity, Rotate)
		s.certsRotateQueue.Done(element)
	}
}

// addCert signs a cert for the identity and cache it.
func (s *SecretManager) fetchCert(identity string) {
	newCert, err := s.caClient.FetchCert(identity)
	if err != nil {
		log.Errorf("fetchCert for [%v] error: %v", identity, err)
		// TODO: backoff retry
		time.AfterFunc(time.Second, func() {
			s.SendCertRequest(identity, RETRY)
		})
		return
	}

	// Save the new certificate in the map and add a record to the rotate queue
	s.StoreCert(identity, newCert)
}

// Set the removed to true for the items in the certsRotateQueue priority queue.
// Delete the certificate and status map corresponding to the identity.
func (s *SecretManager) deleteCert(identity string) {
	s.certsCache.mu.Lock()
	defer s.certsCache.mu.Unlock()
	certificate := s.certsCache.certs[identity]
	if certificate == nil {
		return
	}
	certificate.refCnt--
	log.Debugf("remove identity: %v refCnt : %v", identity, certificate.refCnt)
	if certificate.refCnt == 0 {
		delete(s.certsCache.certs, identity)
		log.Debugf("identity: %v cert deleted", identity)
	}
}

func (s *SecretManager) rotateCert(identity string) {
	s.certsCache.mu.RLock()
	certificate := s.certsCache.certs[identity]
	if certificate == nil {
		s.certsCache.mu.RUnlock()
		log.Debugf("identity: %v cert has been deleted", identity)
		return
	}
	s.certsCache.mu.RUnlock()

	if time.Until(certificate.cert.ExpireTime) >= 1*time.Hour {
		// This can happen when delete a certificate following adding the same one later.
		log.Debugf("cert %s expire at %T, skip rotate now", identity, certificate.cert.ExpireTime)
	}

	go s.fetchCert(identity)
}

func (s *SecretManager) retryFetchCert(identity string) {
	s.certsCache.mu.RLock()
	certificate := s.certsCache.certs[identity]
	if certificate == nil {
		s.certsCache.mu.RUnlock()
		log.Debugf("identity: %v cert has been deleted", identity)
		return
	}
	s.certsCache.mu.RUnlock()

	go s.fetchCert(identity)
}
