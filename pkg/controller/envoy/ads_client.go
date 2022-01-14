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
 * Create: 2021-10-09
 */

package envoy

import (
	"fmt"
	envoyConfigCoreV3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/grpc"
	"openeuler.io/mesh/pkg/nets"
)

type AdsClient struct {
	conn *grpc.ClientConn
}

func NewAdsClient(ads *AdsConfig) (*AdsClient, error) {
	var (
		err error
		conn *grpc.ClientConn
		client = &AdsClient{}
		cluster = ads.Clusters[0]
	)

	switch ads.APIType {
	case envoyConfigCoreV3.ApiConfigSource_GRPC:
		var opts []grpc.DialOption
		opts = append(opts, nets.DefaultDialOption())
		opts = append(opts, grpc.WithInsecure())

		// just using the first address
		if !nets.IsIPAndPort(cluster.Address[0]) {
			opts = append(opts, grpc.WithContextDialer(nets.UnixDialHandler))
		}

		if conn, err = grpc.Dial(cluster.Address[0], opts...); err != nil {
			return nil, err
		}
		log.Debug("grpc dial, %#v", cluster)
	case envoyConfigCoreV3.ApiConfigSource_REST:
		// TODO
		fallthrough
	default:
		return nil, fmt.Errorf("")
	}

	client.conn = conn
	return client, nil
}

func (c *AdsClient) Run(stopCh <-chan struct{}) error {
	// TODO
	go func() {
		select {
		case <-stopCh:
			return
		//default:
		}
	}()

	return nil
}

func (c *AdsClient) Close() error {
	return nil
}
