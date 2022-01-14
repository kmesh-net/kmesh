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
	"net"
	"strings"
)

func DefaultDialOption() grpc.DialOption {
	return grpc.WithDefaultCallOptions(
		grpc.MaxCallRecvMsgSize(math.MaxInt32),
	)
}

func UnixDialHandler(ctx context.Context, addr string) (net.Conn, error) {
	unixAddress, err := net.ResolveUnixAddr("unix", addr)
	if err != nil {
		return nil, err
	}

	return net.DialUnix("unix", nil, unixAddress)
}

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
