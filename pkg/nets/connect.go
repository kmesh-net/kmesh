/*
 * Copyright 2023 The Kmesh Authors.
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

 * Author: LemmyHuang
 * Create: 2022-01-14
 */

package nets

import (
	"context"
	"math"
	"math/rand"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"
	istiogrpc "istio.io/istio/pilot/pkg/grpc"
	istiosecurity "istio.io/istio/pkg/security"
	"istio.io/istio/security/pkg/credentialfetcher"
	"istio.io/istio/security/pkg/nodeagent/caclient"
)

const (
	// MaxRetryInterval retry interval time when reconnect
	MaxRetryInterval = time.Second * 30

	// MaxRetryCount retry max count when reconnect
	MaxRetryCount = 3

	credFetcherTypeEnv = "JWT"
	trustDomainEnv     = "cluster.local"
	jwtPath            = "/var/run/secrets/tokens/istio-token"
	rootCertPath       = "/var/run/secrets/istio/root-cert.pem"
)

// IsIPAndPort returns true if the address format ip:port
func IsIPAndPort(addr string) bool {
	var idx int

	if idx = strings.LastIndex(addr, ":"); idx < 0 {
		return false
	}

	ip := addr[:idx]
	return net.ParseIP(ip) != nil
}

func unixDialHandler(ctx context.Context, addr string) (net.Conn, error) {
	unixAddress, err := net.ResolveUnixAddr("unix", addr)
	if err != nil {
		return nil, err
	}

	return net.DialUnix("unix", nil, unixAddress)
}

func defaultDialOption() grpc.DialOption {
	return grpc.WithDefaultCallOptions(
		grpc.MaxCallRecvMsgSize(math.MaxInt32),
	)
}

// GrpcConnect creates a client connection to the given addr
func GrpcConnect(addr string) (*grpc.ClientConn, error) {
	var (
		err  error
		conn *grpc.ClientConn
	)

	tlsOptions := &istiogrpc.TLSOptions{
		RootCert:      rootCertPath,
		ServerAddress: addr,
	}

	opts, err := istiogrpc.ClientOptions(nil, tlsOptions)
	if err != nil {
		return nil, err
	}

	credFetcher, err := credentialfetcher.NewCredFetcher(credFetcherTypeEnv, trustDomainEnv, jwtPath, "")
	o := &istiosecurity.Options{
		CredFetcher: credFetcher,
	}
	opts = append(opts, grpc.WithPerRPCCredentials(caclient.NewXDSTokenProvider(o)))

	if conn, err = grpc.Dial(addr, opts...); err != nil {
		return nil, err
	}

	return conn, nil
}

// CalculateInterval calculate retry interval
func CalculateInterval(t time.Duration) time.Duration {
	t += MaxRetryInterval / MaxRetryCount
	if t > MaxRetryInterval {
		t = MaxRetryInterval
	}
	return t
}

// CalculateRandTime returns a non-negative pseudo-random time in the half-open interval [0,sed)
func CalculateRandTime(sed int) time.Duration {
	return time.Duration(rand.Intn(sed)) * time.Millisecond
}
