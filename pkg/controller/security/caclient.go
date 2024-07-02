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
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/structpb"
	pb "istio.io/api/security/v1alpha1"
	"istio.io/istio/pkg/security"
	nodeagentutil "istio.io/istio/security/pkg/nodeagent/util"
	pkiutil "istio.io/istio/security/pkg/pki/util"

	"kmesh.net/kmesh/pkg/nets"
)

type caClient struct {
	tlsOpts *tlsOptions
	client  pb.IstioCertificateServiceClient
	conn    *grpc.ClientConn
	opts    *security.Options
}

type tlsOptions struct {
	RootCert string
	Key      string
	Cert     string
}

// NewCaClient create a CA client for CSR sign.
// The following function is adapted from istio NewCitadelClient
// (https://github.com/istio/istio/blob/master/security/pkg/nodeagent/caclient/providers/citadel/client.go)
func newCaClient(opts *security.Options, tlsOpts *tlsOptions) (CaClient, error) {
	var err error

	c := &caClient{
		tlsOpts: tlsOpts,
		opts:    opts,
	}

	conn, err := nets.GrpcConnect(caAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to create grpcconnect : %v", err)
	}

	c.conn = conn
	c.client = pb.NewIstioCertificateServiceClient(conn)
	return c, nil
}

// CsrSend send a grpc request to istio and sign a CSR.
// The following function is adapted from istio CSRSign
// (https://github.com/istio/istio/blob/master/security/pkg/nodeagent/caclient/providers/citadel/client.go)
func (c caClient) CsrSend(csrPEM []byte, certValidsec int64, identity string) ([]string, error) {
	crMeta := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			security.ImpersonatedIdentity: {
				Kind: &structpb.Value_StringValue{StringValue: identity},
			},
		},
	}
	req := &pb.IstioCertificateRequest{
		Csr:              string(csrPEM),
		ValidityDuration: certValidsec,
		Metadata:         crMeta,
	}

	// TODO: support customize clusterID, which is needed for multicluster mesh
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("ClusterID", "Kubernetes"))
	// To handle potential grpc connection disconnection and retry once
	// when certificate acquisition fails. If it still fails, return an error.
	resp, err := c.client.CreateCertificate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("create certificate failed: %v", err)
	}

	if len(resp.CertChain) <= 1 {
		return nil, errors.New("invalid empty CertChain")
	}

	return resp.CertChain, nil
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

// The following function is adapted from istio generateNewSecret
// (https://github.com/istio/istio/blob/master/security/pkg/nodeagent/cache/secretcache.go)
func (c *caClient) FetchCert(identity string) (*security.SecretItem, error) {
	var rootCertPEM []byte

	options := pkiutil.CertOptions{
		Host:       identity,
		RSAKeySize: c.opts.WorkloadRSAKeySize,
		PKCS8Key:   c.opts.Pkcs8Keys,
		ECSigAlg:   pkiutil.SupportedECSignatureAlgorithms(c.opts.ECCSigAlg),
		ECCCurve:   pkiutil.SupportedEllipticCurves(c.opts.ECCCurve),
	}

	// Generate the cert/key, send CSR to CA.
	csrPEM, keyPEM, err := pkiutil.GenCSR(options)
	if err != nil {
		log.Errorf("%s failed to generate key and certificate for CSR: %v", identity, err)
		return nil, err
	}
	certChainPEM, err := c.CsrSend(csrPEM, int64(c.opts.SecretTTL.Seconds()), identity)
	if err != nil {
		return nil, err
	}

	certChain := standardCerts(certChainPEM)

	expireTime, err := nodeagentutil.ParseCertAndGetExpiryTimestamp(certChain)
	if err != nil {
		return nil, fmt.Errorf("%s failed to extract expire time from server certificate in CSR response %+v: %v",
			identity, certChainPEM, err)
	}

	rootCertPEM = []byte(certChainPEM[len(certChainPEM)-1])

	log.Debugf("cert for %v expireTime :%v", identity, expireTime)
	return &security.SecretItem{
		CertificateChain: certChain,
		PrivateKey:       keyPEM,
		ResourceName:     identity,
		CreatedTime:      time.Now(),
		ExpireTime:       expireTime,
		RootCert:         rootCertPEM,
	}, nil
}

func (c *caClient) Close() error {
	return c.conn.Close()
}
