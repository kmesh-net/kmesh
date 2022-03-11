/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: LemmyHuang
 * Create: 2022-01-14
 */

package nets

import (
	"context"
	"google.golang.org/grpc"
	"math"
	"math/rand"
	"net"
	"strings"
	"time"
)

const (
	MaxRetryInterval = time.Second * 30
	MaxRetryCount    = 3
)

func IsIPAndPort(addr string) bool {
	var idx int

	if idx = strings.LastIndex(addr, ":"); idx < 0 {
		return false
	}

	ip := addr[:idx]
	if net.ParseIP(ip) == nil {
		return false
	}

	return true
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

func GrpcConnect(addr string) (*grpc.ClientConn, error) {
	var (
		err error
		conn *grpc.ClientConn
		opts []grpc.DialOption
	)
	opts = append(opts, defaultDialOption())
	opts = append(opts, grpc.WithInsecure())

	if !IsIPAndPort(addr) {
		opts = append(opts, grpc.WithContextDialer(unixDialHandler))
	}

	if conn, err = grpc.Dial(addr, opts...); err != nil {
		return nil, err
	}

	return conn, nil
}

func CalculateInterval(t time.Duration) time.Duration {
	t += MaxRetryInterval / MaxRetryCount
	if t > MaxRetryInterval {
		t = MaxRetryInterval
	}
	return t
}

func CalculateRandTime(sed int) time.Duration {
	return time.Duration(rand.Intn(sed)) * time.Millisecond
}