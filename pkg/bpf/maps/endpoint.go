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

package maps

// #cgo CFLAGS: -I../../bpf/include
// #include "endpoint.h"
import "C"
import "unsafe"

type EndpointAddress struct {
	Protocol	uint32	`json:"protocol"`
	Port		uint32	`json:"port"`
	IPv4		uint32	`json:"ipv4,omitempty"`
	IPv6		[4]uint32	`json:"ipv6,omitempty"`
}

type Endpoint struct {
	Address		EndpointAddress
	LBPriority	uint16	`json:"lb_priority"`
	LBWeight	uint16	`json:"lb_weight,omitempty"`
	LBConnNum	uint16
}

func (ep *Endpoint) CheckInvalidSize() bool {
	return unsafe.Sizeof(*ep) != unsafe.Sizeof(C.endpoint_t)
}

func (ep *Endpoint) Get() error {
	return nil
}

func (ep *Endpoint) Add() error {
	return nil
}

func (ep *Endpoint) Delete() error {
	return nil
}
