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

package kmeshsecurity

import (
	"bytes"
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
	"istio.io/istio/pkg/spiffe"
	nodeagentutil "istio.io/istio/security/pkg/nodeagent/util"
	pkiutil "istio.io/istio/security/pkg/pki/util"
	"kmesh.net/kmesh/pkg/controller/workload"
	"kmesh.net/kmesh/pkg/nets"
)
 
 var tlsOpts *TLSOptions 

 type CitadelClient struct {
	 // It means enable tls connection to Citadel if this is not nil.
	 tlsOpts  *TLSOptions
	 client   pb.IstioCertificateServiceClient
	 conn     *grpc.ClientConn
	 opts     *security.Options
 }

 type TLSOptions struct {
	RootCert string
	Key      string
	Cert     string
}
 
 // NewCitadelClient create a CA client for Citadel.
 func NewCitadelClient(opts *security.Options, tlsOpts *TLSOptions) (*CitadelClient, error) {
	 var err error;
 
	 c := &CitadelClient{
		 tlsOpts:  tlsOpts,
		 opts:     opts,
	 }

	 conn, err := nets.GrpcConnect(CSRSignAddress);
	 if err != nil {
		 log.Errorf("Failed to connect to endpoint %s: %v", opts.CAEndpoint, err)
		 return nil, fmt.Errorf("failed to connect to endpoint %s", opts.CAEndpoint)
	 }
 
	 c.conn = conn
	 c.client = pb.NewIstioCertificateServiceClient(conn)
	 return c, nil
 }

// CSRSign calls Citadel to sign a CSR.
func (c *CitadelClient) CSRSign(csrPEM []byte, certValidTTLInSec int64) ([]string, error) {
	crMetaStruct := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			security.CertSigner: {
				Kind: &structpb.Value_StringValue{StringValue: c.opts.CertSigner},
			},
		},
	}
	req := &pb.IstioCertificateRequest{
		Csr:              string(csrPEM),
		ValidityDuration: certValidTTLInSec,
		Metadata:         crMetaStruct,
	}

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("ClusterID", c.opts.ClusterID))
	resp, err := c.client.CreateCertificate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %v", err)
	}

	defer func() {
                if err != nil {
                        log.Errorf("failed to sign CSR: %v", err)
                        if err := c.reconnect(); err != nil {
                                log.Errorf("failed reconnect: %v", err)
                        }
                }
        }()

	if len(resp.CertChain) <= 1 {
		return nil, errors.New("invalid empty CertChain")
	}

	return resp.CertChain, nil
}

// concatCerts concatenates PEM certificates, making sure each one starts on a new line
func concatCerts(certsPEM []string) []byte {
	if len(certsPEM) == 0 {
		return []byte{}
	}
	var certChain bytes.Buffer
	for i, c := range certsPEM {
		certChain.WriteString(c)
		if i < len(certsPEM)-1 && !strings.HasSuffix(c, "\n") {
			certChain.WriteString("\n")
		}
	}
	return certChain.Bytes()
}

func (c *CitadelClient) fetchCert(uid string) (*security.SecretItem, error) {
	var rootCertPEM []byte
	
	workloadCache := workload.GetCacheByUid(uid)
	if workloadCache == nil {
		log.Errorf("get workloadCache failed")
		err := errors.New("get workloadCache failed")
		return nil, err
	}
	csrHostName := &spiffe.Identity{
		TrustDomain:    workloadCache.TrustDomain, 
		Namespace:      workloadCache.Namespace, 
		ServiceAccount: workloadCache.ServiceAccount,
	}

	options := pkiutil.CertOptions{
		Host:       csrHostName.String(),
		RSAKeySize: c.opts.WorkloadRSAKeySize,
		PKCS8Key:   c.opts.Pkcs8Keys,
		ECSigAlg:   pkiutil.SupportedECSignatureAlgorithms(c.opts.ECCSigAlg),
		ECCCurve:   pkiutil.SupportedEllipticCurves(c.opts.ECCCurve),
	}

	// Generate the cert/key, send CSR to CA.
	csrPEM, keyPEM, err := pkiutil.GenCSR(options)
	if err != nil {
		log.Errorf("%s failed to generate key and certificate for CSR: %v", workloadCache.Name, err)
		return nil, err
	}
	certChainPEM, err := c.CSRSign(csrPEM, int64(c.opts.SecretTTL.Seconds()))
	if err != nil {
		return nil, err
	}
 
	certChain := concatCerts(certChainPEM)
	var expireTime time.Time
	
	if expireTime, err = nodeagentutil.ParseCertAndGetExpiryTimestamp(certChain); err != nil {
		log.Errorf("%s failed to extract expire time from server certificate in CSR response %+v: %v",
		workloadCache.Name, certChainPEM, err)
		return nil, fmt.Errorf("failed to extract expire time from server certificate in CSR response: %v", err)
	}

	rootCertPEM = []byte(certChainPEM[len(certChainPEM)-1])

	return &security.SecretItem{
		CertificateChain: certChain,
		PrivateKey:       keyPEM,
		ResourceName:     workloadCache.Name,
		CreatedTime:      time.Now(),
		ExpireTime:       expireTime,
		RootCert:         rootCertPEM,
	}, nil
 }

 func (c *CitadelClient) reconnect() error {
	if err := c.conn.Close(); err != nil {
		return fmt.Errorf("failed to close connection: %v", err)
	}

	conn, err := nets.GrpcConnect(CSRSignAddress);
	if err != nil {
		return err
	}
	c.conn = conn
	c.client = pb.NewIstioCertificateServiceClient(conn)
	log.Info("recreated connection")
	return nil
}
