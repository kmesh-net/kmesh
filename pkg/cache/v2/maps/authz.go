/*
 * Copyright The Kmesh Authors.
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

 * Author: xsy
 * Create: 2024-07-11
 */

package maps

// #cgo pkg-config: api-v2-c
// #include "deserialization_to_bpf_map.h"
// #include "workloadapi/security/authorization.pb-c.h"
import "C"
import (
	"fmt"
	"unsafe"

	"google.golang.org/protobuf/proto"

	security_v2 "kmesh.net/kmesh/api/v2/workloadapi/security"
)

func authorizationToGolang(goMsg *security_v2.Authorization, cMsg *C.Istio__Security__Authorization) error {
	buf := make([]byte, C.istio__security__authorization__get_packed_size(cMsg))

	C.istio__security__authorization__pack(cMsg, convertToPack(buf))
	if err := proto.Unmarshal(buf, goMsg); err != nil {
		return err
	}
	return nil
}

func authorizationToClang(goMsg *security_v2.Authorization) (*C.Istio__Security__Authorization, error) {
	buf, err := proto.Marshal(goMsg)
	if err != nil {
		return nil, err
	}

	cMsg := C.istio__security__authorization__unpack(nil, C.size_t(len(buf)), convertToPack(buf))
	if cMsg == nil {
		return nil, fmt.Errorf("istio__security__authorization__unpack failed")
	}
	return cMsg, nil
}

func authorizationFreeClang(cMsg *C.Istio__Security__Authorization) {
	C.istio__security__authorization__free_unpacked(cMsg, nil)
}

func authorizationLookup(key string, value *security_v2.Authorization) error {
	var err error

	cKey := stringToClang(key)
	defer stringFreeClang(cKey)

	cMsg := C.deserial_lookup_elem(unsafe.Pointer(cKey), unsafe.Pointer(&C.istio__security__authorization__descriptor))
	if cMsg == nil {
		return fmt.Errorf("authorizationLookup deserial_lookup_elem failed")
	}
	defer C.deserial_free_elem(unsafe.Pointer(cMsg))

	err = authorizationToGolang(value, (*C.Istio__Security__Authorization)(cMsg))
	log.Debugf("authorizationLookup [%s], [%s]", key, value.String())
	return err
}

func AuthorizationUpdate(key string, value *security_v2.Authorization) error {
	log.Debugf("AuthorizationUpdate [%s], [%s]", key, value.String())

	cKey := stringToClang(key)
	defer stringFreeClang(cKey)

	cMsg, err := authorizationToClang(value)
	if err != nil {
		return fmt.Errorf("authorizationUpdate %s", err)
	}
	defer authorizationFreeClang(cMsg)

	testString(key, cKey)
	testAuthorization(value, cMsg)

	ret := C.deserial_update_elem(unsafe.Pointer(cKey), unsafe.Pointer(cMsg))
	if ret != 0 {
		return fmt.Errorf("authorizationUpdate %s deserial_update_elem failed", key)
	}

	return nil
}

func AuthorizationDelete(key string) error {
	log.Debugf("AuthorizationDelete [%s]", key)

	cKey := stringToClang(key)
	defer stringFreeClang(cKey)

	ret := C.deserial_delete_elem(unsafe.Pointer(cKey), unsafe.Pointer(&C.istio__security__authorization__descriptor))
	if ret != 0 {
		return fmt.Errorf("AuthorizationDelete deserial_delete_elem failed")
	}
	return nil
}

func testAuthorization(goMsg *security_v2.Authorization, cMsg *C.Istio__Security__Authorization) {
	msg := &security_v2.Authorization{}

	if err := authorizationToGolang(msg, cMsg); err != nil {
		log.Errorf("testAuthorization authorizationToGolang failed")
	}
	if goMsg.String() != msg.String() {
		log.Errorf("testAuthorization invalid message")
		log.Errorf("testAuthorization [%s]", msg.String())
	}
}
