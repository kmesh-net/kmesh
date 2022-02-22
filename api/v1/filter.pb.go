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

package api

// #cgo CFLAGS: -I../v1-c
// #include "filter.pb-c.h"
import "C"

// CFilter = C.filter_t
type CFilter struct {
	Entry C.filter_t
}

type GoFilter struct {

}

// cFilterChain = C.filter_chain_t
type cFilterChain struct {
	entry C.filter_chain_t
}

type GoFilterChain struct {

}
