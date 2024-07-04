// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Configuration affecting Istio control plane installation version and shape.

package v1alpha1

import (
	bytes "bytes"
	"encoding/json"

	"github.com/golang/protobuf/jsonpb" // nolint: depguard
	"github.com/golang/protobuf/ptypes/wrappers"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// MarshalJSON is a custom marshaler for IstioOperatorSpec
func (in *IstioOperatorSpec) MarshalJSON() ([]byte, error) {
	str, err := OperatorMarshaler.MarshalToString(in)
	return []byte(str), err
}

// UnmarshalJSON is a custom unmarshaler for IstioOperatorSpec
func (in *IstioOperatorSpec) UnmarshalJSON(b []byte) error {
	return OperatorUnmarshaler.Unmarshal(bytes.NewReader(b), in)
}

// MarshalJSON is a custom marshaler for InstallStatus
func (in *InstallStatus) MarshalJSON() ([]byte, error) {
	str, err := OperatorMarshaler.MarshalToString(in)
	return []byte(str), err
}

// UnmarshalJSON is a custom unmarshaler for InstallStatus
func (in *InstallStatus) UnmarshalJSON(b []byte) error {
	return OperatorUnmarshaler.Unmarshal(bytes.NewReader(b), in)
}

// MarshalJSON is a custom marshaler for InstallStatus_VersionStatus
func (in *InstallStatus_VersionStatus) MarshalJSON() ([]byte, error) {
	str, err := OperatorMarshaler.MarshalToString(in)
	return []byte(str), err
}

// UnmarshalJSON is a custom unmarshaler for InstallStatus_VersionStatus
func (in *InstallStatus_VersionStatus) UnmarshalJSON(b []byte) error {
	return OperatorUnmarshaler.Unmarshal(bytes.NewReader(b), in)
}

// UnmarshalJSON implements the json.Unmarshaller interface.
func (in *IntOrString) UnmarshalJSON(value []byte) error {
	if value[0] == '"' {
		in.Type = int64(intstr.String)
		var s string
		err := json.Unmarshal(value, &s)
		if err != nil {
			return err
		}
		in.StrVal = &wrappers.StringValue{Value: s}
		return nil
	}
	in.Type = int64(intstr.Int)
	var s int32
	err := json.Unmarshal(value, &s)
	if err != nil {
		return err
	}
	in.IntVal = &wrappers.Int32Value{Value: s}
	return nil
}

func (in *IntOrString) MarshalJSONPB(_ *jsonpb.Marshaler) ([]byte, error) {
	return in.MarshalJSON()
}

func (in *IntOrString) MarshalJSON() ([]byte, error) {
	if in.IntVal != nil {
		return json.Marshal(in.IntVal.GetValue())
	}
	return json.Marshal(in.StrVal.GetValue())
}

func (in *IntOrString) UnmarshalJSONPB(_ *jsonpb.Unmarshaler, value []byte) error {
	return in.UnmarshalJSON(value)
}

func (in *IntOrString) ToKubernetes() intstr.IntOrString {
	if in.IntVal != nil {
		return intstr.FromInt(int(in.GetIntVal().GetValue()))
	}
	return intstr.FromString(in.GetStrVal().GetValue())
}

var (
	OperatorMarshaler   = &jsonpb.Marshaler{}
	OperatorUnmarshaler = &jsonpb.Unmarshaler{}
)
