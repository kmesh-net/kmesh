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

type certExp struct {
	identity string
	exp      time.Time
}

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

type SecretManager struct {
	caClient *caClient

	// configOptions includes all configurable params for the cache.
	configOptions *istiosecurity.Options

	// storing certificates
	certsCache *certsCache

	// certs rotation priority queue based on exp
	certsRotateQueue workqueue.Interface

	certRequestChan chan certRequest
}

func (s *SecretManager) SendCertRequest(identity string, op int) {
	s.certRequestChan <- certRequest{Identity: identity, Operation: op}
}

func (s *SecretManager) handleCertRequests() {
	for data := range s.certRequestChan {
		identity, op := data.Identity, data.Operation
		switch op {
		case ADD:
			certificate := s.certsCache.addOrUpdate(identity)
			if certificate != nil {
				log.Debugf("add identity: %v refCnt++ : %v\n", identity, certificate.refCnt)
				continue
			}
			// sign cert if only no cert exists for this identity
			go s.addCert(identity)
		case DELETE:
			s.deleteCert(identity)
		case Rotate:
			go s.rotateCert(identity)
		}
	}
}

func newCertCache() *certsCache {
	return &certsCache{
		certs: make(map[string]*certItem),
		mu:    sync.RWMutex{},
	}
}

func (s *SecretManager) storeCert(identity string, newCert *istiosecurity.SecretItem) {
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
	certExp := certExp{
		exp:      newCert.ExpireTime,
		identity: identity,
	}
	// push to rotate queue
	s.certsRotateQueue.Add(certExp)
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

// NewSecretManager creates a new secretManager.s
func NewSecretManager() (*SecretManager, error) {
	tlsOpts := &tlsOptions{
		RootCert: constants.RootCertPath,
	}

	options := NewSecurityOptions()
	caClient, err := newCaClient(options, tlsOpts)
	if err != nil {
		return nil, err
	}

	secretManager := SecretManager{
		caClient:         caClient,
		configOptions:    options,
		certsCache:       newCertCache(),
		certsRotateQueue: workqueue.New(),
		certRequestChan:  make(chan certRequest, maxConcurrentCSR),
	}
	go secretManager.handleCertRequests()
	go secretManager.rotateCerts()
	return &secretManager, nil
}

// Automatically check and rotate when the validity period expires
func (s *SecretManager) rotateCerts() {
	for {
		element, quit := s.certsRotateQueue.Get()
		if quit {
			return
		}
		defer s.certsRotateQueue.Done(element)

		certExp := element.(certExp)
		time.Sleep(time.Until(certExp.exp.Add(-1 * time.Hour)))
		s.SendCertRequest(certExp.identity, Rotate)
	}
}

// addCert signs a cert for the identity and cache it.
func (s *SecretManager) addCert(identity string) {
	newCert, err := s.caClient.fetchCert(identity)
	if err != nil {
		log.Errorf("fetcheCert %v error: %v", identity, err)
		// in case fetchCert failed, retry
		s.certRequestChan <- certRequest{Identity: identity, Operation: ADD}
		return
	}

	// Save the new certificate in the map and add a record to the rotate queue
	s.storeCert(identity, newCert)
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
	s.certsCache.mu.Lock()
	certificate := s.certsCache.certs[identity]
	if certificate == nil {
		s.certsCache.mu.Unlock()
		log.Debugf("identity: %v cert has been deleted", identity)
		return
	}
	s.certsCache.mu.Unlock()

	s.addCert(identity)
}
