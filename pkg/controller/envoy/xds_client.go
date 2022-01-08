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

type XdsClient struct {

}

func NewXdsClient() *XdsClient {
	c := &XdsClient{}
	return c
}

func (c *XdsClient) Run(stopCh <-chan struct{}) error {
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

func (c *XdsClient) Close() error {
	return nil
}
