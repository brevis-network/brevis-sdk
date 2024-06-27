// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.1
// 	protoc        v5.27.1
// source: common/circuit_data.proto

package commonproto

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

type AppCircuitInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	OutputCommitment  string   `protobuf:"bytes,1,opt,name=output_commitment,json=outputCommitment,proto3" json:"output_commitment,omitempty"`
	Vk                string   `protobuf:"bytes,2,opt,name=vk,proto3" json:"vk,omitempty"`
	InputCommitments  []string `protobuf:"bytes,3,rep,name=input_commitments,json=inputCommitments,proto3" json:"input_commitments,omitempty"`
	TogglesCommitment string   `protobuf:"bytes,4,opt,name=toggles_commitment,json=togglesCommitment,proto3" json:"toggles_commitment,omitempty"`
	Toggles           []bool   `protobuf:"varint,5,rep,packed,name=toggles,proto3" json:"toggles,omitempty"`
	UseCallback       bool     `protobuf:"varint,6,opt,name=use_callback,json=useCallback,proto3" json:"use_callback,omitempty"`
	Output            string   `protobuf:"bytes,7,opt,name=output,proto3" json:"output,omitempty"`
}

func (x *AppCircuitInfo) Reset() {
	*x = AppCircuitInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_common_circuit_data_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AppCircuitInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AppCircuitInfo) ProtoMessage() {}

func (x *AppCircuitInfo) ProtoReflect() protoreflect.Message {
	mi := &file_common_circuit_data_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AppCircuitInfo.ProtoReflect.Descriptor instead.
func (*AppCircuitInfo) Descriptor() ([]byte, []int) {
	return file_common_circuit_data_proto_rawDescGZIP(), []int{0}
}

func (x *AppCircuitInfo) GetOutputCommitment() string {
	if x != nil {
		return x.OutputCommitment
	}
	return ""
}

func (x *AppCircuitInfo) GetVk() string {
	if x != nil {
		return x.Vk
	}
	return ""
}

func (x *AppCircuitInfo) GetInputCommitments() []string {
	if x != nil {
		return x.InputCommitments
	}
	return nil
}

func (x *AppCircuitInfo) GetTogglesCommitment() string {
	if x != nil {
		return x.TogglesCommitment
	}
	return ""
}

func (x *AppCircuitInfo) GetToggles() []bool {
	if x != nil {
		return x.Toggles
	}
	return nil
}

func (x *AppCircuitInfo) GetUseCallback() bool {
	if x != nil {
		return x.UseCallback
	}
	return false
}

func (x *AppCircuitInfo) GetOutput() string {
	if x != nil {
		return x.Output
	}
	return ""
}

type AppCirucitInfoWithProof struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	OutputCommitment  string   `protobuf:"bytes,1,opt,name=output_commitment,json=outputCommitment,proto3" json:"output_commitment,omitempty"`
	VkHash            string   `protobuf:"bytes,2,opt,name=vk_hash,json=vkHash,proto3" json:"vk_hash,omitempty"`
	InputCommitments  []string `protobuf:"bytes,3,rep,name=input_commitments,json=inputCommitments,proto3" json:"input_commitments,omitempty"`
	TogglesCommitment string   `protobuf:"bytes,4,opt,name=toggles_commitment,json=togglesCommitment,proto3" json:"toggles_commitment,omitempty"`
	Toggles           []bool   `protobuf:"varint,5,rep,packed,name=toggles,proto3" json:"toggles,omitempty"`
	Output            string   `protobuf:"bytes,6,opt,name=output,proto3" json:"output,omitempty"`
	Proof             string   `protobuf:"bytes,7,opt,name=proof,proto3" json:"proof,omitempty"`
	CallbackAddr      string   `protobuf:"bytes,8,opt,name=callback_addr,json=callbackAddr,proto3" json:"callback_addr,omitempty"`
}

func (x *AppCirucitInfoWithProof) Reset() {
	*x = AppCirucitInfoWithProof{}
	if protoimpl.UnsafeEnabled {
		mi := &file_common_circuit_data_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AppCirucitInfoWithProof) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AppCirucitInfoWithProof) ProtoMessage() {}

func (x *AppCirucitInfoWithProof) ProtoReflect() protoreflect.Message {
	mi := &file_common_circuit_data_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AppCirucitInfoWithProof.ProtoReflect.Descriptor instead.
func (*AppCirucitInfoWithProof) Descriptor() ([]byte, []int) {
	return file_common_circuit_data_proto_rawDescGZIP(), []int{1}
}

func (x *AppCirucitInfoWithProof) GetOutputCommitment() string {
	if x != nil {
		return x.OutputCommitment
	}
	return ""
}

func (x *AppCirucitInfoWithProof) GetVkHash() string {
	if x != nil {
		return x.VkHash
	}
	return ""
}

func (x *AppCirucitInfoWithProof) GetInputCommitments() []string {
	if x != nil {
		return x.InputCommitments
	}
	return nil
}

func (x *AppCirucitInfoWithProof) GetTogglesCommitment() string {
	if x != nil {
		return x.TogglesCommitment
	}
	return ""
}

func (x *AppCirucitInfoWithProof) GetToggles() []bool {
	if x != nil {
		return x.Toggles
	}
	return nil
}

func (x *AppCirucitInfoWithProof) GetOutput() string {
	if x != nil {
		return x.Output
	}
	return ""
}

func (x *AppCirucitInfoWithProof) GetProof() string {
	if x != nil {
		return x.Proof
	}
	return ""
}

func (x *AppCirucitInfoWithProof) GetCallbackAddr() string {
	if x != nil {
		return x.CallbackAddr
	}
	return ""
}

var File_common_circuit_data_proto protoreflect.FileDescriptor

var file_common_circuit_data_proto_rawDesc = []byte{
	0x0a, 0x19, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x63, 0x69, 0x72, 0x63, 0x75, 0x69, 0x74,
	0x5f, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06, 0x63, 0x6f, 0x6d,
	0x6d, 0x6f, 0x6e, 0x22, 0xfe, 0x01, 0x0a, 0x0e, 0x41, 0x70, 0x70, 0x43, 0x69, 0x72, 0x63, 0x75,
	0x69, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x2b, 0x0a, 0x11, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74,
	0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x10, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d,
	0x65, 0x6e, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x76, 0x6b, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x02, 0x76, 0x6b, 0x12, 0x2b, 0x0a, 0x11, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x5f, 0x63, 0x6f, 0x6d,
	0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x10,
	0x69, 0x6e, 0x70, 0x75, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x73,
	0x12, 0x2d, 0x0a, 0x12, 0x74, 0x6f, 0x67, 0x67, 0x6c, 0x65, 0x73, 0x5f, 0x63, 0x6f, 0x6d, 0x6d,
	0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x74, 0x6f,
	0x67, 0x67, 0x6c, 0x65, 0x73, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x12,
	0x18, 0x0a, 0x07, 0x74, 0x6f, 0x67, 0x67, 0x6c, 0x65, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x08,
	0x52, 0x07, 0x74, 0x6f, 0x67, 0x67, 0x6c, 0x65, 0x73, 0x12, 0x21, 0x0a, 0x0c, 0x75, 0x73, 0x65,
	0x5f, 0x63, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x18, 0x06, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x0b, 0x75, 0x73, 0x65, 0x43, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x12, 0x16, 0x0a, 0x06,
	0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x6f, 0x75,
	0x74, 0x70, 0x75, 0x74, 0x22, 0xa8, 0x02, 0x0a, 0x17, 0x41, 0x70, 0x70, 0x43, 0x69, 0x72, 0x75,
	0x63, 0x69, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x57, 0x69, 0x74, 0x68, 0x50, 0x72, 0x6f, 0x6f, 0x66,
	0x12, 0x2b, 0x0a, 0x11, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69,
	0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x6f, 0x75, 0x74,
	0x70, 0x75, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x17, 0x0a,
	0x07, 0x76, 0x6b, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06,
	0x76, 0x6b, 0x48, 0x61, 0x73, 0x68, 0x12, 0x2b, 0x0a, 0x11, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x5f,
	0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28,
	0x09, 0x52, 0x10, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65,
	0x6e, 0x74, 0x73, 0x12, 0x2d, 0x0a, 0x12, 0x74, 0x6f, 0x67, 0x67, 0x6c, 0x65, 0x73, 0x5f, 0x63,
	0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x11, 0x74, 0x6f, 0x67, 0x67, 0x6c, 0x65, 0x73, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65,
	0x6e, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x74, 0x6f, 0x67, 0x67, 0x6c, 0x65, 0x73, 0x18, 0x05, 0x20,
	0x03, 0x28, 0x08, 0x52, 0x07, 0x74, 0x6f, 0x67, 0x67, 0x6c, 0x65, 0x73, 0x12, 0x16, 0x0a, 0x06,
	0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x6f, 0x75,
	0x74, 0x70, 0x75, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x07, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x05, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x12, 0x23, 0x0a, 0x0d, 0x63, 0x61,
	0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x18, 0x08, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0c, 0x63, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x41, 0x64, 0x64, 0x72, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_common_circuit_data_proto_rawDescOnce sync.Once
	file_common_circuit_data_proto_rawDescData = file_common_circuit_data_proto_rawDesc
)

func file_common_circuit_data_proto_rawDescGZIP() []byte {
	file_common_circuit_data_proto_rawDescOnce.Do(func() {
		file_common_circuit_data_proto_rawDescData = protoimpl.X.CompressGZIP(file_common_circuit_data_proto_rawDescData)
	})
	return file_common_circuit_data_proto_rawDescData
}

var file_common_circuit_data_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_common_circuit_data_proto_goTypes = []interface{}{
	(*AppCircuitInfo)(nil),          // 0: common.AppCircuitInfo
	(*AppCirucitInfoWithProof)(nil), // 1: common.AppCirucitInfoWithProof
}
var file_common_circuit_data_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_common_circuit_data_proto_init() }
func file_common_circuit_data_proto_init() {
	if File_common_circuit_data_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_common_circuit_data_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AppCircuitInfo); i {
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
		file_common_circuit_data_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AppCirucitInfoWithProof); i {
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
			RawDescriptor: file_common_circuit_data_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_common_circuit_data_proto_goTypes,
		DependencyIndexes: file_common_circuit_data_proto_depIdxs,
		MessageInfos:      file_common_circuit_data_proto_msgTypes,
	}.Build()
	File_common_circuit_data_proto = out.File
	file_common_circuit_data_proto_rawDesc = nil
	file_common_circuit_data_proto_goTypes = nil
	file_common_circuit_data_proto_depIdxs = nil
}
