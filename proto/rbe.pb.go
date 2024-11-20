// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.2
// 	protoc        v5.28.3
// source: proto/rbe.proto

package proto

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

type G1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Bytes []byte `protobuf:"bytes,1,opt,name=bytes,proto3" json:"bytes,omitempty"`
}

func (x *G1) Reset() {
	*x = G1{}
	mi := &file_proto_rbe_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *G1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*G1) ProtoMessage() {}

func (x *G1) ProtoReflect() protoreflect.Message {
	mi := &file_proto_rbe_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use G1.ProtoReflect.Descriptor instead.
func (*G1) Descriptor() ([]byte, []int) {
	return file_proto_rbe_proto_rawDescGZIP(), []int{0}
}

func (x *G1) GetBytes() []byte {
	if x != nil {
		return x.Bytes
	}
	return nil
}

type G2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Bytes []byte `protobuf:"bytes,1,opt,name=bytes,proto3" json:"bytes,omitempty"`
}

func (x *G2) Reset() {
	*x = G2{}
	mi := &file_proto_rbe_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *G2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*G2) ProtoMessage() {}

func (x *G2) ProtoReflect() protoreflect.Message {
	mi := &file_proto_rbe_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use G2.ProtoReflect.Descriptor instead.
func (*G2) Descriptor() ([]byte, []int) {
	return file_proto_rbe_proto_rawDescGZIP(), []int{1}
}

func (x *G2) GetBytes() []byte {
	if x != nil {
		return x.Bytes
	}
	return nil
}

type CRS struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	HParamsG1 []*G1 `protobuf:"bytes,1,rep,name=hParamsG1,proto3" json:"hParamsG1,omitempty"`
	HParamsG2 []*G2 `protobuf:"bytes,2,rep,name=hParamsG2,proto3" json:"hParamsG2,omitempty"`
}

func (x *CRS) Reset() {
	*x = CRS{}
	mi := &file_proto_rbe_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CRS) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CRS) ProtoMessage() {}

func (x *CRS) ProtoReflect() protoreflect.Message {
	mi := &file_proto_rbe_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CRS.ProtoReflect.Descriptor instead.
func (*CRS) Descriptor() ([]byte, []int) {
	return file_proto_rbe_proto_rawDescGZIP(), []int{2}
}

func (x *CRS) GetHParamsG1() []*G1 {
	if x != nil {
		return x.HParamsG1
	}
	return nil
}

func (x *CRS) GetHParamsG2() []*G2 {
	if x != nil {
		return x.HParamsG2
	}
	return nil
}

type PublicParams struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MaxUsers    int32 `protobuf:"varint,1,opt,name=maxUsers,proto3" json:"maxUsers,omitempty"`
	BlockSize   int32 `protobuf:"varint,2,opt,name=blockSize,proto3" json:"blockSize,omitempty"`
	NumBlocks   int32 `protobuf:"varint,3,opt,name=numBlocks,proto3" json:"numBlocks,omitempty"`
	G1          *G1   `protobuf:"bytes,4,opt,name=g1,proto3" json:"g1,omitempty"`
	G2          *G2   `protobuf:"bytes,5,opt,name=g2,proto3" json:"g2,omitempty"`
	Crs         *CRS  `protobuf:"bytes,6,opt,name=crs,proto3" json:"crs,omitempty"`
	Commitments []*G1 `protobuf:"bytes,7,rep,name=commitments,proto3" json:"commitments,omitempty"`
}

func (x *PublicParams) Reset() {
	*x = PublicParams{}
	mi := &file_proto_rbe_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PublicParams) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublicParams) ProtoMessage() {}

func (x *PublicParams) ProtoReflect() protoreflect.Message {
	mi := &file_proto_rbe_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublicParams.ProtoReflect.Descriptor instead.
func (*PublicParams) Descriptor() ([]byte, []int) {
	return file_proto_rbe_proto_rawDescGZIP(), []int{3}
}

func (x *PublicParams) GetMaxUsers() int32 {
	if x != nil {
		return x.MaxUsers
	}
	return 0
}

func (x *PublicParams) GetBlockSize() int32 {
	if x != nil {
		return x.BlockSize
	}
	return 0
}

func (x *PublicParams) GetNumBlocks() int32 {
	if x != nil {
		return x.NumBlocks
	}
	return 0
}

func (x *PublicParams) GetG1() *G1 {
	if x != nil {
		return x.G1
	}
	return nil
}

func (x *PublicParams) GetG2() *G2 {
	if x != nil {
		return x.G2
	}
	return nil
}

func (x *PublicParams) GetCrs() *CRS {
	if x != nil {
		return x.Crs
	}
	return nil
}

func (x *PublicParams) GetCommitments() []*G1 {
	if x != nil {
		return x.Commitments
	}
	return nil
}

var File_proto_rbe_proto protoreflect.FileDescriptor

var file_proto_rbe_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x72, 0x62, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x09, 0x72, 0x62, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x1a, 0x0a, 0x02,
	0x47, 0x31, 0x12, 0x14, 0x0a, 0x05, 0x62, 0x79, 0x74, 0x65, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x05, 0x62, 0x79, 0x74, 0x65, 0x73, 0x22, 0x1a, 0x0a, 0x02, 0x47, 0x32, 0x12, 0x14,
	0x0a, 0x05, 0x62, 0x79, 0x74, 0x65, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x62,
	0x79, 0x74, 0x65, 0x73, 0x22, 0x5f, 0x0a, 0x03, 0x43, 0x52, 0x53, 0x12, 0x2b, 0x0a, 0x09, 0x68,
	0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x47, 0x31, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0d,
	0x2e, 0x72, 0x62, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x47, 0x31, 0x52, 0x09, 0x68,
	0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x47, 0x31, 0x12, 0x2b, 0x0a, 0x09, 0x68, 0x50, 0x61, 0x72,
	0x61, 0x6d, 0x73, 0x47, 0x32, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x72, 0x62,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x47, 0x32, 0x52, 0x09, 0x68, 0x50, 0x61, 0x72,
	0x61, 0x6d, 0x73, 0x47, 0x32, 0x22, 0xf7, 0x01, 0x0a, 0x0c, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x12, 0x1a, 0x0a, 0x08, 0x6d, 0x61, 0x78, 0x55, 0x73, 0x65,
	0x72, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52, 0x08, 0x6d, 0x61, 0x78, 0x55, 0x73, 0x65,
	0x72, 0x73, 0x12, 0x1c, 0x0a, 0x09, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x53, 0x69, 0x7a, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x05, 0x52, 0x09, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x53, 0x69, 0x7a, 0x65,
	0x12, 0x1c, 0x0a, 0x09, 0x6e, 0x75, 0x6d, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x73, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x05, 0x52, 0x09, 0x6e, 0x75, 0x6d, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x73, 0x12, 0x1d,
	0x0a, 0x02, 0x67, 0x31, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x72, 0x62, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x47, 0x31, 0x52, 0x02, 0x67, 0x31, 0x12, 0x1d, 0x0a,
	0x02, 0x67, 0x32, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x72, 0x62, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x47, 0x32, 0x52, 0x02, 0x67, 0x32, 0x12, 0x20, 0x0a, 0x03,
	0x63, 0x72, 0x73, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x72, 0x62, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x43, 0x52, 0x53, 0x52, 0x03, 0x63, 0x72, 0x73, 0x12, 0x2f,
	0x0a, 0x0b, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x07, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x0d, 0x2e, 0x72, 0x62, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e,
	0x47, 0x31, 0x52, 0x0b, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x42,
	0x1d, 0x5a, 0x1b, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x74,
	0x63, 0x6c, 0x61, 0x62, 0x2f, 0x72, 0x62, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_rbe_proto_rawDescOnce sync.Once
	file_proto_rbe_proto_rawDescData = file_proto_rbe_proto_rawDesc
)

func file_proto_rbe_proto_rawDescGZIP() []byte {
	file_proto_rbe_proto_rawDescOnce.Do(func() {
		file_proto_rbe_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_rbe_proto_rawDescData)
	})
	return file_proto_rbe_proto_rawDescData
}

var file_proto_rbe_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_proto_rbe_proto_goTypes = []any{
	(*G1)(nil),           // 0: rbe.proto.G1
	(*G2)(nil),           // 1: rbe.proto.G2
	(*CRS)(nil),          // 2: rbe.proto.CRS
	(*PublicParams)(nil), // 3: rbe.proto.PublicParams
}
var file_proto_rbe_proto_depIdxs = []int32{
	0, // 0: rbe.proto.CRS.hParamsG1:type_name -> rbe.proto.G1
	1, // 1: rbe.proto.CRS.hParamsG2:type_name -> rbe.proto.G2
	0, // 2: rbe.proto.PublicParams.g1:type_name -> rbe.proto.G1
	1, // 3: rbe.proto.PublicParams.g2:type_name -> rbe.proto.G2
	2, // 4: rbe.proto.PublicParams.crs:type_name -> rbe.proto.CRS
	0, // 5: rbe.proto.PublicParams.commitments:type_name -> rbe.proto.G1
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_proto_rbe_proto_init() }
func file_proto_rbe_proto_init() {
	if File_proto_rbe_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proto_rbe_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proto_rbe_proto_goTypes,
		DependencyIndexes: file_proto_rbe_proto_depIdxs,
		MessageInfos:      file_proto_rbe_proto_msgTypes,
	}.Build()
	File_proto_rbe_proto = out.File
	file_proto_rbe_proto_rawDesc = nil
	file_proto_rbe_proto_goTypes = nil
	file_proto_rbe_proto_depIdxs = nil
}
