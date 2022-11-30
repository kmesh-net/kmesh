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
 * Create: 2022-03-01
 */

package maps

// #cgo pkg-config: api-v2-c
// #include "deserialization_to_bpf_map.h"
// #include "route/route.pb-c.h"
import "C"
import (
	"fmt"
	"unsafe"

	"google.golang.org/protobuf/proto"
	route_v2 "openeuler.io/mesh/api/v2/route"
)

func routeConfigToGolang(goMsg *route_v2.RouteConfiguration, cMsg *C.Route__RouteConfiguration) error {
	buf := make([]byte, C.route__route_configuration__get_packed_size(cMsg))

	C.route__route_configuration__pack(cMsg, convertToPack(buf))
	if err := proto.Unmarshal(buf, goMsg); err != nil {
		return err
	}
	return nil
}

func routeConfigToClang(goMsg *route_v2.RouteConfiguration) (*C.Route__RouteConfiguration, error) {
	buf, err := proto.Marshal(goMsg)
	if err != nil {
		return nil, err
	}

	cMsg := C.route__route_configuration__unpack(nil, C.size_t(len(buf)), convertToPack(buf))
	if cMsg == nil {
		return nil, fmt.Errorf("route__route_configuration__unpack failed")
	}
	return cMsg, nil
}

func routeConfigFreeClang(cMsg *C.Route__RouteConfiguration) {
	C.route__route_configuration__free_unpacked(cMsg, nil)
}

func RouteConfigLookup(key string, value *route_v2.RouteConfiguration) error {
	var err error

	cKey := stringToClang(key)
	defer stringFreeClang(cKey)

	cMsg := C.deserial_lookup_elem(unsafe.Pointer(cKey), unsafe.Pointer(&C.route__route_configuration__descriptor))
	if cMsg == nil {
		return fmt.Errorf("RouteLookup deserial_lookup_elem failed")
	}
	defer C.deserial_free_elem(unsafe.Pointer(cMsg))

	err = routeConfigToGolang(value, (*C.Route__RouteConfiguration)(cMsg))
	log.Debugf("RouteConfigLookup [%s], [%s]", key, value.String())
	return err
}

func RouteConfigUpdate(key string, value *route_v2.RouteConfiguration) error {
	log.Debugf("RouteConfigUpdate [%s], [%s]", key, value.String())

	cKey := stringToClang(key)
	defer stringFreeClang(cKey)

	cMsg, err := routeConfigToClang(value)
	if err != nil {
		return fmt.Errorf("RouteConfigUpdate %s", err)
	}
	defer routeConfigFreeClang(cMsg)

	testString(key, cKey)
	testRouteConfiguration(value, cMsg)

	ret := C.deserial_update_elem(unsafe.Pointer(cKey), unsafe.Pointer(cMsg))
	if ret != 0 {
		return fmt.Errorf("RouteConfigUpdate deserial_update_elem failed")
	}

	return nil
}

func RouteConfigDelete(key string) error {
	log.Debugf("RouteConfigDelete [%s]", key)

	cKey := stringToClang(key)
	defer stringFreeClang(cKey)

	ret := C.deserial_delete_elem(unsafe.Pointer(cKey), unsafe.Pointer(&C.route__route_configuration__descriptor))
	if ret != 0 {
		return fmt.Errorf("RouteConfigDelete deserial_delete_elem failed")
	}
	return nil
}

func testRouteConfiguration(goMsg *route_v2.RouteConfiguration, cMsg *C.Route__RouteConfiguration) {
	msg := &route_v2.RouteConfiguration{}

	if err := routeConfigToGolang(msg, cMsg); err != nil {
		log.Errorf("testRouteConfiguration routeConfigToGolang failed")
	}
	if goMsg.String() != msg.String() {
		log.Errorf("testRouteConfiguration invalid message")
		log.Errorf("testRouteConfiguration [%s]", msg.String())
	}
}
