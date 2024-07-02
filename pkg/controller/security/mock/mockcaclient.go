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

package mock

import (
	"encoding/pem"
	"fmt"
	"path"
	"strings"
	"time"

	"istio.io/istio/pkg/security"
	nodeagentutil "istio.io/istio/security/pkg/nodeagent/util"
	"istio.io/istio/security/pkg/pki/util"
	"istio.io/pkg/log"
)

var (
	sampleKeyCertsPath = "./testdata"
	caCertPath         = path.Join(sampleKeyCertsPath, "ca-cert.pem")
	caKeyPath          = path.Join(sampleKeyCertsPath, "ca-key.pem")
	certChainPath      = []string{path.Join(sampleKeyCertsPath, "cert-chain.pem")}
	rootCertPath       = path.Join(sampleKeyCertsPath, "root-cert.pem")
)

type CAClient struct {
	bundle         *util.KeyCertBundle
	certLifetime   time.Duration
	GeneratedCerts [][]string // Cache the generated certificates for verification purpose.
	opts           *security.Options
}

// NewMockCaClient create a CA client for CSR sign.
// The following function is adapted from istio NewMockCitadelClient
// (https://github.com/istio/istio/blob/1.20.0/security/pkg/nodeagent/caclient/providers/mock/mockcaclient.go)
func NewMockCaClient(opts *security.Options, certLifetime time.Duration) (*CAClient, error) {
	cl := CAClient{
		certLifetime: certLifetime,
		opts:         opts,
	}
	bundle, err := util.NewVerifiedKeyCertBundleFromFile(caCertPath, caKeyPath, certChainPath, rootCertPath)
	if err != nil {
		return nil, fmt.Errorf("mock ca client creation error: %v", err)
	}
	cl.bundle = bundle
	return &cl, nil
}

// CsrSend send a grpc request to istio and sign a CSR.
// The following function is adapted from istio CSRSign
// (https://github.com/istio/istio/blob/1.20.0/security/pkg/nodeagent/caclient/providers/mock/mockcaclient.go)
func (c *CAClient) CsrSend(csrPEM []byte, certValidsec int64, identity string) ([]string, error) {
	signingCert, signingKey, certChain, rootCert := c.bundle.GetAll()
	csr, err := util.ParsePemEncodedCSR(csrPEM)
	if err != nil {
		return nil, fmt.Errorf("csr sign error: %v", err)
	}
	subjectIDs := []string{"test"}
	certBytes, err := util.GenCertFromCSR(csr, signingCert, csr.PublicKey, *signingKey, subjectIDs, c.certLifetime, false)
	if err != nil {
		return nil, fmt.Errorf("csr sign error: %v", err)
	}

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}
	cert := pem.EncodeToMemory(block)

	ret := []string{string(cert), string(certChain), string(rootCert)}
	return ret, nil
}

func (c *CAClient) Close() error {
	return nil
}

// The following function is adapted from istio generateNewSecret
// (https://github.com/istio/istio/blob/master/security/pkg/nodeagent/cache/secretcache.go)
func (c *CAClient) FetchCert(identity string) (*security.SecretItem, error) {
	var rootCertPEM []byte

	options := util.CertOptions{
		Host:       identity,
		RSAKeySize: c.opts.WorkloadRSAKeySize,
		PKCS8Key:   c.opts.Pkcs8Keys,
		ECSigAlg:   util.SupportedECSignatureAlgorithms(c.opts.ECCSigAlg),
		ECCCurve:   util.SupportedEllipticCurves(c.opts.ECCCurve),
	}

	// Generate the cert/key, send CSR to CA.
	csrPEM, keyPEM, err := util.GenCSR(options)
	if err != nil {
		log.Errorf("%s failed to generate key and certificate for CSR: %v", identity, err)
		return nil, err
	}
	certChainPEM, err := c.CsrSend(csrPEM, int64(c.opts.SecretTTL.Seconds()), identity)
	if err != nil {
		return nil, fmt.Errorf("failed to get certChainPEM due to %v", err)
	}

	certChain := standardCerts(certChainPEM)

	expireTime, err := nodeagentutil.ParseCertAndGetExpiryTimestamp(certChain)
	if err != nil {
		return nil, fmt.Errorf("%s failed to extract expire time from server certificate in CSR response %+v: %v",
			identity, certChainPEM, err)
	}

	rootCertPEM = []byte(certChainPEM[len(certChainPEM)-1])

	log.Debugf("cert for %v ExpireTime :%v", identity, expireTime)
	return &security.SecretItem{
		CertificateChain: certChain,
		PrivateKey:       keyPEM,
		ResourceName:     identity,
		CreatedTime:      time.Now(),
		ExpireTime:       expireTime,
		RootCert:         rootCertPEM,
	}, nil
}

// Standard the PEM certificates, ensuring that each certificate starts on a new line
func standardCerts(certsPEM []string) []byte {
	var certChain strings.Builder
	for i, c := range certsPEM {
		certChain.WriteString(c)
		if i < len(certsPEM)-1 && !strings.HasSuffix(c, "\n") {
			certChain.WriteString("\n")
		}
	}
	return []byte(certChain.String())
}
