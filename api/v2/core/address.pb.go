// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v5.28.1
// source: api/core/address.proto

package core

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type SocketAddress_Protocol int32

const (
	SocketAddress_TCP SocketAddress_Protocol = 0
	SocketAddress_UDP SocketAddress_Protocol = 1
)

// Enum value maps for SocketAddress_Protocol.
var (
	SocketAddress_Protocol_name = map[int32]string{
		0: "TCP",
		1: "UDP",
	}
	SocketAddress_Protocol_value = map[string]int32{
		"TCP": 0,
		"UDP": 1,
	}
)

func (x SocketAddress_Protocol) Enum() *SocketAddress_Protocol {
	p := new(SocketAddress_Protocol)
	*p = x
	return p
}

func (x SocketAddress_Protocol) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (SocketAddress_Protocol) Descriptor() protoreflect.EnumDescriptor {
	return file_api_core_address_proto_enumTypes[0].Descriptor()
}

func (SocketAddress_Protocol) Type() protoreflect.EnumType {
	return &file_api_core_address_proto_enumTypes[0]
}

func (x SocketAddress_Protocol) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use SocketAddress_Protocol.Descriptor instead.
func (SocketAddress_Protocol) EnumDescriptor() ([]byte, []int) {
	return file_api_core_address_proto_rawDescGZIP(), []int{0, 0}
}

type SocketAddress struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Protocol SocketAddress_Protocol `protobuf:"varint,1,opt,name=protocol,proto3,enum=core.SocketAddress_Protocol" json:"protocol,omitempty"`
	Port     uint32                 `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`
	Ipv4     uint32                 `protobuf:"varint,3,opt,name=ipv4,proto3" json:"ipv4,omitempty"`
}

func (x *SocketAddress) Reset() {
	*x = SocketAddress{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_core_address_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SocketAddress) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SocketAddress) ProtoMessage() {}

func (x *SocketAddress) ProtoReflect() protoreflect.Message {
	mi := &file_api_core_address_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SocketAddress.ProtoReflect.Descriptor instead.
func (*SocketAddress) Descriptor() ([]byte, []int) {
	return file_api_core_address_proto_rawDescGZIP(), []int{0}
}

func (x *SocketAddress) GetProtocol() SocketAddress_Protocol {
	if x != nil {
		return x.Protocol
	}
	return SocketAddress_TCP
}

func (x *SocketAddress) GetPort() uint32 {
	if x != nil {
		return x.Port
	}
	return 0
}

func (x *SocketAddress) GetIpv4() uint32 {
	if x != nil {
		return x.Ipv4
	}
	return 0
}

type CidrRange struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AddressPrefix string `protobuf:"bytes,1,opt,name=address_prefix,json=addressPrefix,proto3" json:"address_prefix,omitempty"`
	PrefixLen     uint32 `protobuf:"varint,2,opt,name=prefix_len,json=prefixLen,proto3" json:"prefix_len,omitempty"`
}

func (x *CidrRange) Reset() {
	*x = CidrRange{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_core_address_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CidrRange) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CidrRange) ProtoMessage() {}

func (x *CidrRange) ProtoReflect() protoreflect.Message {
	mi := &file_api_core_address_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CidrRange.ProtoReflect.Descriptor instead.
func (*CidrRange) Descriptor() ([]byte, []int) {
	return file_api_core_address_proto_rawDescGZIP(), []int{1}
}

func (x *CidrRange) GetAddressPrefix() string {
	if x != nil {
		return x.AddressPrefix
	}
	return ""
}

func (x *CidrRange) GetPrefixLen() uint32 {
	if x != nil {
		return x.PrefixLen
	}
	return 0
}

var File_api_core_address_proto protoreflect.FileDescriptor

var file_api_core_address_proto_rawDesc = []byte{
	0x0a, 0x16, 0x61, 0x70, 0x69, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x61, 0x64, 0x64, 0x72, 0x65,
	0x73, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x04, 0x63, 0x6f, 0x72, 0x65, 0x22, 0x8f,
	0x01, 0x0a, 0x0d, 0x53, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73,
	0x12, 0x38, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0e, 0x32, 0x1c, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x53, 0x6f, 0x63, 0x6b, 0x65, 0x74,
	0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x2e, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c,
	0x52, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x6f,
	0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x12,
	0x0a, 0x04, 0x69, 0x70, 0x76, 0x34, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x69, 0x70,
	0x76, 0x34, 0x22, 0x1c, 0x0a, 0x08, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x12, 0x07,
	0x0a, 0x03, 0x54, 0x43, 0x50, 0x10, 0x00, 0x12, 0x07, 0x0a, 0x03, 0x55, 0x44, 0x50, 0x10, 0x01,
	0x22, 0x51, 0x0a, 0x09, 0x43, 0x69, 0x64, 0x72, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x12, 0x25, 0x0a,
	0x0e, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x50, 0x72,
	0x65, 0x66, 0x69, 0x78, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x5f, 0x6c,
	0x65, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78,
	0x4c, 0x65, 0x6e, 0x42, 0x1f, 0x5a, 0x1d, 0x6b, 0x6d, 0x65, 0x73, 0x68, 0x2e, 0x6e, 0x65, 0x74,
	0x2f, 0x6b, 0x6d, 0x65, 0x73, 0x68, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x3b,
	0x63, 0x6f, 0x72, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_api_core_address_proto_rawDescOnce sync.Once
	file_api_core_address_proto_rawDescData = file_api_core_address_proto_rawDesc
)

func file_api_core_address_proto_rawDescGZIP() []byte {
	file_api_core_address_proto_rawDescOnce.Do(func() {
		file_api_core_address_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_core_address_proto_rawDescData)
	})
	return file_api_core_address_proto_rawDescData
}

var file_api_core_address_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_api_core_address_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_api_core_address_proto_goTypes = []any{
	(SocketAddress_Protocol)(0), // 0: core.SocketAddress.Protocol
	(*SocketAddress)(nil),       // 1: core.SocketAddress
	(*CidrRange)(nil),           // 2: core.CidrRange
}
var file_api_core_address_proto_depIdxs = []int32{
	0, // 0: core.SocketAddress.protocol:type_name -> core.SocketAddress.Protocol
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_api_core_address_proto_init() }
func file_api_core_address_proto_init() {
	if File_api_core_address_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_core_address_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*SocketAddress); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_core_address_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*CidrRange); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_core_address_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_api_core_address_proto_goTypes,
		DependencyIndexes: file_api_core_address_proto_depIdxs,
		EnumInfos:         file_api_core_address_proto_enumTypes,
		MessageInfos:      file_api_core_address_proto_msgTypes,
	}.Build()
	File_api_core_address_proto = out.File
	file_api_core_address_proto_rawDesc = nil
	file_api_core_address_proto_goTypes = nil
	file_api_core_address_proto_depIdxs = nil
}
