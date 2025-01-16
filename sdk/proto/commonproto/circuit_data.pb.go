// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.2
// 	protoc        v5.29.2
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
	state            protoimpl.MessageState `protogen:"open.v1"`
	OutputCommitment string                 `protobuf:"bytes,1,opt,name=output_commitment,json=outputCommitment,proto3" json:"output_commitment,omitempty"`
	Vk               string                 `protobuf:"bytes,2,opt,name=vk,proto3" json:"vk,omitempty"`
	InputCommitments []string               `protobuf:"bytes,3,rep,name=input_commitments,json=inputCommitments,proto3" json:"input_commitments,omitempty"`
	// Deprecated: Marked as deprecated in common/circuit_data.proto.
	TogglesCommitment    string `protobuf:"bytes,4,opt,name=toggles_commitment,json=togglesCommitment,proto3" json:"toggles_commitment,omitempty"`
	Toggles              []bool `protobuf:"varint,5,rep,packed,name=toggles,proto3" json:"toggles,omitempty"`
	UseCallback          bool   `protobuf:"varint,6,opt,name=use_callback,json=useCallback,proto3" json:"use_callback,omitempty"`
	Output               string `protobuf:"bytes,7,opt,name=output,proto3" json:"output,omitempty"`
	VkHash               string `protobuf:"bytes,8,opt,name=vk_hash,json=vkHash,proto3" json:"vk_hash,omitempty"`
	InputCommitmentsRoot string `protobuf:"bytes,9,opt,name=input_commitments_root,json=inputCommitmentsRoot,proto3" json:"input_commitments_root,omitempty"`
	Witness              string `protobuf:"bytes,10,opt,name=witness,proto3" json:"witness,omitempty"`
	MaxReceipts          uint32 `protobuf:"varint,11,opt,name=max_receipts,json=maxReceipts,proto3" json:"max_receipts,omitempty"`
	MaxStorage           uint32 `protobuf:"varint,12,opt,name=max_storage,json=maxStorage,proto3" json:"max_storage,omitempty"`
	MaxTx                uint32 `protobuf:"varint,13,opt,name=max_tx,json=maxTx,proto3" json:"max_tx,omitempty"`
	MaxNumDataPoints     uint32 `protobuf:"varint,14,opt,name=max_num_data_points,json=maxNumDataPoints,proto3" json:"max_num_data_points,omitempty"`
	unknownFields        protoimpl.UnknownFields
	sizeCache            protoimpl.SizeCache
}

func (x *AppCircuitInfo) Reset() {
	*x = AppCircuitInfo{}
	mi := &file_common_circuit_data_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AppCircuitInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AppCircuitInfo) ProtoMessage() {}

func (x *AppCircuitInfo) ProtoReflect() protoreflect.Message {
	mi := &file_common_circuit_data_proto_msgTypes[0]
	if x != nil {
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

// Deprecated: Marked as deprecated in common/circuit_data.proto.
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

func (x *AppCircuitInfo) GetVkHash() string {
	if x != nil {
		return x.VkHash
	}
	return ""
}

func (x *AppCircuitInfo) GetInputCommitmentsRoot() string {
	if x != nil {
		return x.InputCommitmentsRoot
	}
	return ""
}

func (x *AppCircuitInfo) GetWitness() string {
	if x != nil {
		return x.Witness
	}
	return ""
}

func (x *AppCircuitInfo) GetMaxReceipts() uint32 {
	if x != nil {
		return x.MaxReceipts
	}
	return 0
}

func (x *AppCircuitInfo) GetMaxStorage() uint32 {
	if x != nil {
		return x.MaxStorage
	}
	return 0
}

func (x *AppCircuitInfo) GetMaxTx() uint32 {
	if x != nil {
		return x.MaxTx
	}
	return 0
}

func (x *AppCircuitInfo) GetMaxNumDataPoints() uint32 {
	if x != nil {
		return x.MaxNumDataPoints
	}
	return 0
}

type AppCircuitInfoWithProof struct {
	state            protoimpl.MessageState `protogen:"open.v1"`
	OutputCommitment string                 `protobuf:"bytes,1,opt,name=output_commitment,json=outputCommitment,proto3" json:"output_commitment,omitempty"`
	VkHash           string                 `protobuf:"bytes,2,opt,name=vk_hash,json=vkHash,proto3" json:"vk_hash,omitempty"`
	InputCommitments []string               `protobuf:"bytes,3,rep,name=input_commitments,json=inputCommitments,proto3" json:"input_commitments,omitempty"`
	// Deprecated: Marked as deprecated in common/circuit_data.proto.
	TogglesCommitment    string `protobuf:"bytes,4,opt,name=toggles_commitment,json=togglesCommitment,proto3" json:"toggles_commitment,omitempty"`
	Toggles              []bool `protobuf:"varint,5,rep,packed,name=toggles,proto3" json:"toggles,omitempty"`
	Output               string `protobuf:"bytes,6,opt,name=output,proto3" json:"output,omitempty"`
	Proof                string `protobuf:"bytes,7,opt,name=proof,proto3" json:"proof,omitempty"`
	CallbackAddr         string `protobuf:"bytes,8,opt,name=callback_addr,json=callbackAddr,proto3" json:"callback_addr,omitempty"`
	InputCommitmentsRoot string `protobuf:"bytes,9,opt,name=input_commitments_root,json=inputCommitmentsRoot,proto3" json:"input_commitments_root,omitempty"`
	Witness              string `protobuf:"bytes,10,opt,name=witness,proto3" json:"witness,omitempty"`
	MaxReceipts          uint32 `protobuf:"varint,11,opt,name=max_receipts,json=maxReceipts,proto3" json:"max_receipts,omitempty"`
	MaxStorage           uint32 `protobuf:"varint,12,opt,name=max_storage,json=maxStorage,proto3" json:"max_storage,omitempty"`
	MaxTx                uint32 `protobuf:"varint,13,opt,name=max_tx,json=maxTx,proto3" json:"max_tx,omitempty"`
	MaxNumDataPoints     uint32 `protobuf:"varint,14,opt,name=max_num_data_points,json=maxNumDataPoints,proto3" json:"max_num_data_points,omitempty"`
	unknownFields        protoimpl.UnknownFields
	sizeCache            protoimpl.SizeCache
}

func (x *AppCircuitInfoWithProof) Reset() {
	*x = AppCircuitInfoWithProof{}
	mi := &file_common_circuit_data_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AppCircuitInfoWithProof) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AppCircuitInfoWithProof) ProtoMessage() {}

func (x *AppCircuitInfoWithProof) ProtoReflect() protoreflect.Message {
	mi := &file_common_circuit_data_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AppCircuitInfoWithProof.ProtoReflect.Descriptor instead.
func (*AppCircuitInfoWithProof) Descriptor() ([]byte, []int) {
	return file_common_circuit_data_proto_rawDescGZIP(), []int{1}
}

func (x *AppCircuitInfoWithProof) GetOutputCommitment() string {
	if x != nil {
		return x.OutputCommitment
	}
	return ""
}

func (x *AppCircuitInfoWithProof) GetVkHash() string {
	if x != nil {
		return x.VkHash
	}
	return ""
}

func (x *AppCircuitInfoWithProof) GetInputCommitments() []string {
	if x != nil {
		return x.InputCommitments
	}
	return nil
}

// Deprecated: Marked as deprecated in common/circuit_data.proto.
func (x *AppCircuitInfoWithProof) GetTogglesCommitment() string {
	if x != nil {
		return x.TogglesCommitment
	}
	return ""
}

func (x *AppCircuitInfoWithProof) GetToggles() []bool {
	if x != nil {
		return x.Toggles
	}
	return nil
}

func (x *AppCircuitInfoWithProof) GetOutput() string {
	if x != nil {
		return x.Output
	}
	return ""
}

func (x *AppCircuitInfoWithProof) GetProof() string {
	if x != nil {
		return x.Proof
	}
	return ""
}

func (x *AppCircuitInfoWithProof) GetCallbackAddr() string {
	if x != nil {
		return x.CallbackAddr
	}
	return ""
}

func (x *AppCircuitInfoWithProof) GetInputCommitmentsRoot() string {
	if x != nil {
		return x.InputCommitmentsRoot
	}
	return ""
}

func (x *AppCircuitInfoWithProof) GetWitness() string {
	if x != nil {
		return x.Witness
	}
	return ""
}

func (x *AppCircuitInfoWithProof) GetMaxReceipts() uint32 {
	if x != nil {
		return x.MaxReceipts
	}
	return 0
}

func (x *AppCircuitInfoWithProof) GetMaxStorage() uint32 {
	if x != nil {
		return x.MaxStorage
	}
	return 0
}

func (x *AppCircuitInfoWithProof) GetMaxTx() uint32 {
	if x != nil {
		return x.MaxTx
	}
	return 0
}

func (x *AppCircuitInfoWithProof) GetMaxNumDataPoints() uint32 {
	if x != nil {
		return x.MaxNumDataPoints
	}
	return 0
}

type VmAppCircuitInfo struct {
	state                     protoimpl.MessageState `protogen:"open.v1"`
	Toggles                   []bool                 `protobuf:"varint,1,rep,packed,name=toggles,proto3" json:"toggles,omitempty"`
	MaxReceipts               uint32                 `protobuf:"varint,2,opt,name=max_receipts,json=maxReceipts,proto3" json:"max_receipts,omitempty"`
	MaxStorage                uint32                 `protobuf:"varint,3,opt,name=max_storage,json=maxStorage,proto3" json:"max_storage,omitempty"`
	MaxTx                     uint32                 `protobuf:"varint,4,opt,name=max_tx,json=maxTx,proto3" json:"max_tx,omitempty"`
	MaxNumDataPoints          uint32                 `protobuf:"varint,5,opt,name=max_num_data_points,json=maxNumDataPoints,proto3" json:"max_num_data_points,omitempty"`
	Output                    string                 `protobuf:"bytes,6,opt,name=output,proto3" json:"output,omitempty"`                                                                              // abi encode of the output struct of vm. example: abi.encode(struct{sum, avg})
	ConstraintJson            string                 `protobuf:"bytes,7,opt,name=constraint_json,json=constraintJson,proto3" json:"constraint_json,omitempty"`                                        // for agg prover, gateway do not use it.
	ProofWithPublicValuesJson string                 `protobuf:"bytes,8,opt,name=proof_with_public_values_json,json=proofWithPublicValuesJson,proto3" json:"proof_with_public_values_json,omitempty"` // for agg prover, gateway do not use it.
	unknownFields             protoimpl.UnknownFields
	sizeCache                 protoimpl.SizeCache
}

func (x *VmAppCircuitInfo) Reset() {
	*x = VmAppCircuitInfo{}
	mi := &file_common_circuit_data_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *VmAppCircuitInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VmAppCircuitInfo) ProtoMessage() {}

func (x *VmAppCircuitInfo) ProtoReflect() protoreflect.Message {
	mi := &file_common_circuit_data_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VmAppCircuitInfo.ProtoReflect.Descriptor instead.
func (*VmAppCircuitInfo) Descriptor() ([]byte, []int) {
	return file_common_circuit_data_proto_rawDescGZIP(), []int{2}
}

func (x *VmAppCircuitInfo) GetToggles() []bool {
	if x != nil {
		return x.Toggles
	}
	return nil
}

func (x *VmAppCircuitInfo) GetMaxReceipts() uint32 {
	if x != nil {
		return x.MaxReceipts
	}
	return 0
}

func (x *VmAppCircuitInfo) GetMaxStorage() uint32 {
	if x != nil {
		return x.MaxStorage
	}
	return 0
}

func (x *VmAppCircuitInfo) GetMaxTx() uint32 {
	if x != nil {
		return x.MaxTx
	}
	return 0
}

func (x *VmAppCircuitInfo) GetMaxNumDataPoints() uint32 {
	if x != nil {
		return x.MaxNumDataPoints
	}
	return 0
}

func (x *VmAppCircuitInfo) GetOutput() string {
	if x != nil {
		return x.Output
	}
	return ""
}

func (x *VmAppCircuitInfo) GetConstraintJson() string {
	if x != nil {
		return x.ConstraintJson
	}
	return ""
}

func (x *VmAppCircuitInfo) GetProofWithPublicValuesJson() string {
	if x != nil {
		return x.ProofWithPublicValuesJson
	}
	return ""
}

var File_common_circuit_data_proto protoreflect.FileDescriptor

var file_common_circuit_data_proto_rawDesc = []byte{
	0x0a, 0x19, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x63, 0x69, 0x72, 0x63, 0x75, 0x69, 0x74,
	0x5f, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06, 0x63, 0x6f, 0x6d,
	0x6d, 0x6f, 0x6e, 0x22, 0xf5, 0x03, 0x0a, 0x0e, 0x41, 0x70, 0x70, 0x43, 0x69, 0x72, 0x63, 0x75,
	0x69, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x2b, 0x0a, 0x11, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74,
	0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x10, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d,
	0x65, 0x6e, 0x74, 0x12, 0x0e, 0x0a, 0x02, 0x76, 0x6b, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x02, 0x76, 0x6b, 0x12, 0x2b, 0x0a, 0x11, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x5f, 0x63, 0x6f, 0x6d,
	0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x10,
	0x69, 0x6e, 0x70, 0x75, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x73,
	0x12, 0x31, 0x0a, 0x12, 0x74, 0x6f, 0x67, 0x67, 0x6c, 0x65, 0x73, 0x5f, 0x63, 0x6f, 0x6d, 0x6d,
	0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x42, 0x02, 0x18, 0x01,
	0x52, 0x11, 0x74, 0x6f, 0x67, 0x67, 0x6c, 0x65, 0x73, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d,
	0x65, 0x6e, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x74, 0x6f, 0x67, 0x67, 0x6c, 0x65, 0x73, 0x18, 0x05,
	0x20, 0x03, 0x28, 0x08, 0x52, 0x07, 0x74, 0x6f, 0x67, 0x67, 0x6c, 0x65, 0x73, 0x12, 0x21, 0x0a,
	0x0c, 0x75, 0x73, 0x65, 0x5f, 0x63, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x0b, 0x75, 0x73, 0x65, 0x43, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b,
	0x12, 0x16, 0x0a, 0x06, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x06, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x12, 0x17, 0x0a, 0x07, 0x76, 0x6b, 0x5f, 0x68,
	0x61, 0x73, 0x68, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x76, 0x6b, 0x48, 0x61, 0x73,
	0x68, 0x12, 0x34, 0x0a, 0x16, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69,
	0x74, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x5f, 0x72, 0x6f, 0x6f, 0x74, 0x18, 0x09, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x14, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65,
	0x6e, 0x74, 0x73, 0x52, 0x6f, 0x6f, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x77, 0x69, 0x74, 0x6e, 0x65,
	0x73, 0x73, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x77, 0x69, 0x74, 0x6e, 0x65, 0x73,
	0x73, 0x12, 0x21, 0x0a, 0x0c, 0x6d, 0x61, 0x78, 0x5f, 0x72, 0x65, 0x63, 0x65, 0x69, 0x70, 0x74,
	0x73, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x6d, 0x61, 0x78, 0x52, 0x65, 0x63, 0x65,
	0x69, 0x70, 0x74, 0x73, 0x12, 0x1f, 0x0a, 0x0b, 0x6d, 0x61, 0x78, 0x5f, 0x73, 0x74, 0x6f, 0x72,
	0x61, 0x67, 0x65, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x6d, 0x61, 0x78, 0x53, 0x74,
	0x6f, 0x72, 0x61, 0x67, 0x65, 0x12, 0x15, 0x0a, 0x06, 0x6d, 0x61, 0x78, 0x5f, 0x74, 0x78, 0x18,
	0x0d, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x6d, 0x61, 0x78, 0x54, 0x78, 0x12, 0x2d, 0x0a, 0x13,
	0x6d, 0x61, 0x78, 0x5f, 0x6e, 0x75, 0x6d, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x70, 0x6f, 0x69,
	0x6e, 0x74, 0x73, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x10, 0x6d, 0x61, 0x78, 0x4e, 0x75,
	0x6d, 0x44, 0x61, 0x74, 0x61, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x73, 0x22, 0x86, 0x04, 0x0a, 0x17,
	0x41, 0x70, 0x70, 0x43, 0x69, 0x72, 0x63, 0x75, 0x69, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x57, 0x69,
	0x74, 0x68, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x12, 0x2b, 0x0a, 0x11, 0x6f, 0x75, 0x74, 0x70, 0x75,
	0x74, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x10, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74,
	0x6d, 0x65, 0x6e, 0x74, 0x12, 0x17, 0x0a, 0x07, 0x76, 0x6b, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x76, 0x6b, 0x48, 0x61, 0x73, 0x68, 0x12, 0x2b, 0x0a,
	0x11, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e,
	0x74, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x09, 0x52, 0x10, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x43,
	0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x12, 0x31, 0x0a, 0x12, 0x74, 0x6f,
	0x67, 0x67, 0x6c, 0x65, 0x73, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x42, 0x02, 0x18, 0x01, 0x52, 0x11, 0x74, 0x6f, 0x67, 0x67,
	0x6c, 0x65, 0x73, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x18, 0x0a,
	0x07, 0x74, 0x6f, 0x67, 0x67, 0x6c, 0x65, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x08, 0x52, 0x07,
	0x74, 0x6f, 0x67, 0x67, 0x6c, 0x65, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x6f, 0x75, 0x74, 0x70, 0x75,
	0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x12,
	0x14, 0x0a, 0x05, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x70, 0x72, 0x6f, 0x6f, 0x66, 0x12, 0x23, 0x0a, 0x0d, 0x63, 0x61, 0x6c, 0x6c, 0x62, 0x61, 0x63,
	0x6b, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x63, 0x61,
	0x6c, 0x6c, 0x62, 0x61, 0x63, 0x6b, 0x41, 0x64, 0x64, 0x72, 0x12, 0x34, 0x0a, 0x16, 0x69, 0x6e,
	0x70, 0x75, 0x74, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x5f,
	0x72, 0x6f, 0x6f, 0x74, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x14, 0x69, 0x6e, 0x70, 0x75,
	0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x52, 0x6f, 0x6f, 0x74,
	0x12, 0x18, 0x0a, 0x07, 0x77, 0x69, 0x74, 0x6e, 0x65, 0x73, 0x73, 0x18, 0x0a, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x77, 0x69, 0x74, 0x6e, 0x65, 0x73, 0x73, 0x12, 0x21, 0x0a, 0x0c, 0x6d, 0x61,
	0x78, 0x5f, 0x72, 0x65, 0x63, 0x65, 0x69, 0x70, 0x74, 0x73, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x0b, 0x6d, 0x61, 0x78, 0x52, 0x65, 0x63, 0x65, 0x69, 0x70, 0x74, 0x73, 0x12, 0x1f, 0x0a,
	0x0b, 0x6d, 0x61, 0x78, 0x5f, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x18, 0x0c, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x0a, 0x6d, 0x61, 0x78, 0x53, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x12, 0x15,
	0x0a, 0x06, 0x6d, 0x61, 0x78, 0x5f, 0x74, 0x78, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05,
	0x6d, 0x61, 0x78, 0x54, 0x78, 0x12, 0x2d, 0x0a, 0x13, 0x6d, 0x61, 0x78, 0x5f, 0x6e, 0x75, 0x6d,
	0x5f, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x73, 0x18, 0x0e, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x10, 0x6d, 0x61, 0x78, 0x4e, 0x75, 0x6d, 0x44, 0x61, 0x74, 0x61, 0x50, 0x6f,
	0x69, 0x6e, 0x74, 0x73, 0x22, 0xb9, 0x02, 0x0a, 0x10, 0x56, 0x6d, 0x41, 0x70, 0x70, 0x43, 0x69,
	0x72, 0x63, 0x75, 0x69, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x18, 0x0a, 0x07, 0x74, 0x6f, 0x67,
	0x67, 0x6c, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x08, 0x52, 0x07, 0x74, 0x6f, 0x67, 0x67,
	0x6c, 0x65, 0x73, 0x12, 0x21, 0x0a, 0x0c, 0x6d, 0x61, 0x78, 0x5f, 0x72, 0x65, 0x63, 0x65, 0x69,
	0x70, 0x74, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x6d, 0x61, 0x78, 0x52, 0x65,
	0x63, 0x65, 0x69, 0x70, 0x74, 0x73, 0x12, 0x1f, 0x0a, 0x0b, 0x6d, 0x61, 0x78, 0x5f, 0x73, 0x74,
	0x6f, 0x72, 0x61, 0x67, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x6d, 0x61, 0x78,
	0x53, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x12, 0x15, 0x0a, 0x06, 0x6d, 0x61, 0x78, 0x5f, 0x74,
	0x78, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x6d, 0x61, 0x78, 0x54, 0x78, 0x12, 0x2d,
	0x0a, 0x13, 0x6d, 0x61, 0x78, 0x5f, 0x6e, 0x75, 0x6d, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x70,
	0x6f, 0x69, 0x6e, 0x74, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x10, 0x6d, 0x61, 0x78,
	0x4e, 0x75, 0x6d, 0x44, 0x61, 0x74, 0x61, 0x50, 0x6f, 0x69, 0x6e, 0x74, 0x73, 0x12, 0x16, 0x0a,
	0x06, 0x6f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x6f,
	0x75, 0x74, 0x70, 0x75, 0x74, 0x12, 0x27, 0x0a, 0x0f, 0x63, 0x6f, 0x6e, 0x73, 0x74, 0x72, 0x61,
	0x69, 0x6e, 0x74, 0x5f, 0x6a, 0x73, 0x6f, 0x6e, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e,
	0x63, 0x6f, 0x6e, 0x73, 0x74, 0x72, 0x61, 0x69, 0x6e, 0x74, 0x4a, 0x73, 0x6f, 0x6e, 0x12, 0x40,
	0x0a, 0x1d, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x77, 0x69, 0x74, 0x68, 0x5f, 0x70, 0x75, 0x62,
	0x6c, 0x69, 0x63, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x5f, 0x6a, 0x73, 0x6f, 0x6e, 0x18,
	0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x19, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x57, 0x69, 0x74, 0x68,
	0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x4a, 0x73, 0x6f, 0x6e,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
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

var file_common_circuit_data_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_common_circuit_data_proto_goTypes = []any{
	(*AppCircuitInfo)(nil),          // 0: common.AppCircuitInfo
	(*AppCircuitInfoWithProof)(nil), // 1: common.AppCircuitInfoWithProof
	(*VmAppCircuitInfo)(nil),        // 2: common.VmAppCircuitInfo
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_common_circuit_data_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
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
