// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v4.25.3
// source: sdk/types.proto

package sdkproto

import (
	commonproto "github.com/brevis-network/brevis-sdk/sdk/proto/commonproto"
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

// ReceiptData is a request for proof for some data under an EVM receipt
type ReceiptData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BlockNum uint64 `protobuf:"varint,1,opt,name=block_num,json=blockNum,proto3" json:"block_num,omitempty"`
	// hex encoded tx hash
	TxHash string `protobuf:"bytes,2,opt,name=tx_hash,json=txHash,proto3" json:"tx_hash,omitempty"`
	// must at least contain one field
	Fields             []*Field `protobuf:"bytes,3,rep,name=fields,proto3" json:"fields,omitempty"`
	ReceiptDataJsonHex string   `protobuf:"bytes,4,opt,name=receipt_data_json_hex,json=receiptDataJsonHex,proto3" json:"receipt_data_json_hex,omitempty"`
}

func (x *ReceiptData) Reset() {
	*x = ReceiptData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sdk_types_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ReceiptData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ReceiptData) ProtoMessage() {}

func (x *ReceiptData) ProtoReflect() protoreflect.Message {
	mi := &file_sdk_types_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ReceiptData.ProtoReflect.Descriptor instead.
func (*ReceiptData) Descriptor() ([]byte, []int) {
	return file_sdk_types_proto_rawDescGZIP(), []int{0}
}

func (x *ReceiptData) GetBlockNum() uint64 {
	if x != nil {
		return x.BlockNum
	}
	return 0
}

func (x *ReceiptData) GetTxHash() string {
	if x != nil {
		return x.TxHash
	}
	return ""
}

func (x *ReceiptData) GetFields() []*Field {
	if x != nil {
		return x.Fields
	}
	return nil
}

func (x *ReceiptData) GetReceiptDataJsonHex() string {
	if x != nil {
		return x.ReceiptDataJsonHex
	}
	return ""
}

// Field represents a field in an EVM log that we want the validity to be proven by Brevis
type Field struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// address. the contract which emitted the log
	Contract string `protobuf:"bytes,1,opt,name=contract,proto3" json:"contract,omitempty"`
	// the index of the log in the transaction receipt, starting from 0.
	LogPos uint32 `protobuf:"varint,2,opt,name=log_pos,json=logPos,proto3" json:"log_pos,omitempty"`
	// the event id (aka topic[0]) of the log
	EventId string `protobuf:"bytes,3,opt,name=event_id,json=eventId,proto3" json:"event_id,omitempty"`
	// the value of the field we want to prove
	Value string `protobuf:"bytes,4,opt,name=value,proto3" json:"value,omitempty"`
	// true if the field is a topic, false if the field is in log data
	IsTopic bool `protobuf:"varint,5,opt,name=is_topic,json=isTopic,proto3" json:"is_topic,omitempty"`
	// the index of the field in the log
	FieldIndex uint32 `protobuf:"varint,6,opt,name=field_index,json=fieldIndex,proto3" json:"field_index,omitempty"`
}

func (x *Field) Reset() {
	*x = Field{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sdk_types_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Field) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Field) ProtoMessage() {}

func (x *Field) ProtoReflect() protoreflect.Message {
	mi := &file_sdk_types_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Field.ProtoReflect.Descriptor instead.
func (*Field) Descriptor() ([]byte, []int) {
	return file_sdk_types_proto_rawDescGZIP(), []int{1}
}

func (x *Field) GetContract() string {
	if x != nil {
		return x.Contract
	}
	return ""
}

func (x *Field) GetLogPos() uint32 {
	if x != nil {
		return x.LogPos
	}
	return 0
}

func (x *Field) GetEventId() string {
	if x != nil {
		return x.EventId
	}
	return ""
}

func (x *Field) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

func (x *Field) GetIsTopic() bool {
	if x != nil {
		return x.IsTopic
	}
	return false
}

func (x *Field) GetFieldIndex() uint32 {
	if x != nil {
		return x.FieldIndex
	}
	return 0
}

// StorageData is a request for proof for some data in an EVM storage slot
type StorageData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// from which block to fetch the storage value
	BlockNum uint64 `protobuf:"varint,1,opt,name=block_num,json=blockNum,proto3" json:"block_num,omitempty"`
	// hex encoded address of the account
	Address string `protobuf:"bytes,2,opt,name=address,proto3" json:"address,omitempty"`
	// the hex encoded "slot" of a storage.
	// see https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html
	Slot string `protobuf:"bytes,3,opt,name=slot,proto3" json:"slot,omitempty"`
	// the value stored in the storage slot. decoding is based on Go's big.Int SetString.
	// must not exceed 32 bytes
	Value              string `protobuf:"bytes,4,opt,name=value,proto3" json:"value,omitempty"`
	StorageDataJsonHex string `protobuf:"bytes,5,opt,name=storage_data_json_hex,json=storageDataJsonHex,proto3" json:"storage_data_json_hex,omitempty"`
}

func (x *StorageData) Reset() {
	*x = StorageData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sdk_types_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StorageData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StorageData) ProtoMessage() {}

func (x *StorageData) ProtoReflect() protoreflect.Message {
	mi := &file_sdk_types_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StorageData.ProtoReflect.Descriptor instead.
func (*StorageData) Descriptor() ([]byte, []int) {
	return file_sdk_types_proto_rawDescGZIP(), []int{2}
}

func (x *StorageData) GetBlockNum() uint64 {
	if x != nil {
		return x.BlockNum
	}
	return 0
}

func (x *StorageData) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

func (x *StorageData) GetSlot() string {
	if x != nil {
		return x.Slot
	}
	return ""
}

func (x *StorageData) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

func (x *StorageData) GetStorageDataJsonHex() string {
	if x != nil {
		return x.StorageDataJsonHex
	}
	return ""
}

// TransactionData is a request for proof for some EVM transaction
// Only transaction type 0 and 2 are supported
type TransactionData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// hex encoded tx hash
	Hash     string `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
	ChainId  uint64 `protobuf:"varint,2,opt,name=chain_id,json=chainId,proto3" json:"chain_id,omitempty"`
	BlockNum uint64 `protobuf:"varint,3,opt,name=block_num,json=blockNum,proto3" json:"block_num,omitempty"`
	Nonce    uint64 `protobuf:"varint,4,opt,name=nonce,proto3" json:"nonce,omitempty"`
	// this field represents `GasPrice` for legacy tx (type 0) and `GasTipCap` for dynamic fee tx (type 2)
	GasTipCapOrGasPrice string `protobuf:"bytes,5,opt,name=gas_tip_cap_or_gas_price,json=gasTipCapOrGasPrice,proto3" json:"gas_tip_cap_or_gas_price,omitempty"`
	// this field is ignored for legacy tx (type 0) and represents `GasFeeCap` for dynamic fee tx (type 2)
	GasFeeCap string `protobuf:"bytes,6,opt,name=gas_fee_cap,json=gasFeeCap,proto3" json:"gas_fee_cap,omitempty"`
	GasLimit  uint64 `protobuf:"varint,7,opt,name=gas_limit,json=gasLimit,proto3" json:"gas_limit,omitempty"`
	// address
	From string `protobuf:"bytes,8,opt,name=from,proto3" json:"from,omitempty"`
	// address
	To string `protobuf:"bytes,9,opt,name=to,proto3" json:"to,omitempty"`
	// decoding is based on Go's big.Int SetString. must be less than uint256 max
	Value                  string `protobuf:"bytes,10,opt,name=value,proto3" json:"value,omitempty"`
	TransactionDataJsonHex string `protobuf:"bytes,11,opt,name=transaction_data_json_hex,json=transactionDataJsonHex,proto3" json:"transaction_data_json_hex,omitempty"`
}

func (x *TransactionData) Reset() {
	*x = TransactionData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sdk_types_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TransactionData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TransactionData) ProtoMessage() {}

func (x *TransactionData) ProtoReflect() protoreflect.Message {
	mi := &file_sdk_types_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TransactionData.ProtoReflect.Descriptor instead.
func (*TransactionData) Descriptor() ([]byte, []int) {
	return file_sdk_types_proto_rawDescGZIP(), []int{3}
}

func (x *TransactionData) GetHash() string {
	if x != nil {
		return x.Hash
	}
	return ""
}

func (x *TransactionData) GetChainId() uint64 {
	if x != nil {
		return x.ChainId
	}
	return 0
}

func (x *TransactionData) GetBlockNum() uint64 {
	if x != nil {
		return x.BlockNum
	}
	return 0
}

func (x *TransactionData) GetNonce() uint64 {
	if x != nil {
		return x.Nonce
	}
	return 0
}

func (x *TransactionData) GetGasTipCapOrGasPrice() string {
	if x != nil {
		return x.GasTipCapOrGasPrice
	}
	return ""
}

func (x *TransactionData) GetGasFeeCap() string {
	if x != nil {
		return x.GasFeeCap
	}
	return ""
}

func (x *TransactionData) GetGasLimit() uint64 {
	if x != nil {
		return x.GasLimit
	}
	return 0
}

func (x *TransactionData) GetFrom() string {
	if x != nil {
		return x.From
	}
	return ""
}

func (x *TransactionData) GetTo() string {
	if x != nil {
		return x.To
	}
	return ""
}

func (x *TransactionData) GetValue() string {
	if x != nil {
		return x.Value
	}
	return ""
}

func (x *TransactionData) GetTransactionDataJsonHex() string {
	if x != nil {
		return x.TransactionDataJsonHex
	}
	return ""
}

type CustomInput struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	JsonBytes string `protobuf:"bytes,1,opt,name=json_bytes,json=jsonBytes,proto3" json:"json_bytes,omitempty"`
}

func (x *CustomInput) Reset() {
	*x = CustomInput{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sdk_types_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CustomInput) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CustomInput) ProtoMessage() {}

func (x *CustomInput) ProtoReflect() protoreflect.Message {
	mi := &file_sdk_types_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CustomInput.ProtoReflect.Descriptor instead.
func (*CustomInput) Descriptor() ([]byte, []int) {
	return file_sdk_types_proto_rawDescGZIP(), []int{4}
}

func (x *CustomInput) GetJsonBytes() string {
	if x != nil {
		return x.JsonBytes
	}
	return ""
}

type IndexedReceipt struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Index uint32       `protobuf:"varint,1,opt,name=index,proto3" json:"index,omitempty"`
	Data  *ReceiptData `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
}

func (x *IndexedReceipt) Reset() {
	*x = IndexedReceipt{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sdk_types_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IndexedReceipt) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IndexedReceipt) ProtoMessage() {}

func (x *IndexedReceipt) ProtoReflect() protoreflect.Message {
	mi := &file_sdk_types_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IndexedReceipt.ProtoReflect.Descriptor instead.
func (*IndexedReceipt) Descriptor() ([]byte, []int) {
	return file_sdk_types_proto_rawDescGZIP(), []int{5}
}

func (x *IndexedReceipt) GetIndex() uint32 {
	if x != nil {
		return x.Index
	}
	return 0
}

func (x *IndexedReceipt) GetData() *ReceiptData {
	if x != nil {
		return x.Data
	}
	return nil
}

type IndexedStorage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Index uint32       `protobuf:"varint,1,opt,name=index,proto3" json:"index,omitempty"`
	Data  *StorageData `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
}

func (x *IndexedStorage) Reset() {
	*x = IndexedStorage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sdk_types_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IndexedStorage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IndexedStorage) ProtoMessage() {}

func (x *IndexedStorage) ProtoReflect() protoreflect.Message {
	mi := &file_sdk_types_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IndexedStorage.ProtoReflect.Descriptor instead.
func (*IndexedStorage) Descriptor() ([]byte, []int) {
	return file_sdk_types_proto_rawDescGZIP(), []int{6}
}

func (x *IndexedStorage) GetIndex() uint32 {
	if x != nil {
		return x.Index
	}
	return 0
}

func (x *IndexedStorage) GetData() *StorageData {
	if x != nil {
		return x.Data
	}
	return nil
}

type IndexedTransaction struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Index uint32           `protobuf:"varint,1,opt,name=index,proto3" json:"index,omitempty"`
	Data  *TransactionData `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
}

func (x *IndexedTransaction) Reset() {
	*x = IndexedTransaction{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sdk_types_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IndexedTransaction) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IndexedTransaction) ProtoMessage() {}

func (x *IndexedTransaction) ProtoReflect() protoreflect.Message {
	mi := &file_sdk_types_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IndexedTransaction.ProtoReflect.Descriptor instead.
func (*IndexedTransaction) Descriptor() ([]byte, []int) {
	return file_sdk_types_proto_rawDescGZIP(), []int{7}
}

func (x *IndexedTransaction) GetIndex() uint32 {
	if x != nil {
		return x.Index
	}
	return 0
}

func (x *IndexedTransaction) GetData() *TransactionData {
	if x != nil {
		return x.Data
	}
	return nil
}

type Proof struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Proof       string                      `protobuf:"bytes,1,opt,name=proof,proto3" json:"proof,omitempty"`
	CircuitInfo *commonproto.AppCircuitInfo `protobuf:"bytes,2,opt,name=circuit_info,json=circuitInfo,proto3" json:"circuit_info,omitempty"`
}

func (x *Proof) Reset() {
	*x = Proof{}
	if protoimpl.UnsafeEnabled {
		mi := &file_sdk_types_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Proof) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Proof) ProtoMessage() {}

func (x *Proof) ProtoReflect() protoreflect.Message {
	mi := &file_sdk_types_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Proof.ProtoReflect.Descriptor instead.
func (*Proof) Descriptor() ([]byte, []int) {
	return file_sdk_types_proto_rawDescGZIP(), []int{8}
}

func (x *Proof) GetProof() string {
	if x != nil {
		return x.Proof
	}
	return ""
}

func (x *Proof) GetCircuitInfo() *commonproto.AppCircuitInfo {
	if x != nil {
		return x.CircuitInfo
	}
	return nil
}

var File_sdk_types_proto protoreflect.FileDescriptor

var file_sdk_types_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x73, 0x64, 0x6b, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x03, 0x73, 0x64, 0x6b, 0x1a, 0x19, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x63,
	0x69, 0x72, 0x63, 0x75, 0x69, 0x74, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0x9a, 0x01, 0x0a, 0x0b, 0x52, 0x65, 0x63, 0x65, 0x69, 0x70, 0x74, 0x44, 0x61, 0x74,
	0x61, 0x12, 0x1b, 0x0a, 0x09, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x6e, 0x75, 0x6d, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x04, 0x52, 0x08, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x4e, 0x75, 0x6d, 0x12, 0x17,
	0x0a, 0x07, 0x74, 0x78, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x06, 0x74, 0x78, 0x48, 0x61, 0x73, 0x68, 0x12, 0x22, 0x0a, 0x06, 0x66, 0x69, 0x65, 0x6c, 0x64,
	0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x0a, 0x2e, 0x73, 0x64, 0x6b, 0x2e, 0x46, 0x69,
	0x65, 0x6c, 0x64, 0x52, 0x06, 0x66, 0x69, 0x65, 0x6c, 0x64, 0x73, 0x12, 0x31, 0x0a, 0x15, 0x72,
	0x65, 0x63, 0x65, 0x69, 0x70, 0x74, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x6a, 0x73, 0x6f, 0x6e,
	0x5f, 0x68, 0x65, 0x78, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x12, 0x72, 0x65, 0x63, 0x65,
	0x69, 0x70, 0x74, 0x44, 0x61, 0x74, 0x61, 0x4a, 0x73, 0x6f, 0x6e, 0x48, 0x65, 0x78, 0x22, 0xa9,
	0x01, 0x0a, 0x05, 0x46, 0x69, 0x65, 0x6c, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x61, 0x63, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x61, 0x63, 0x74, 0x12, 0x17, 0x0a, 0x07, 0x6c, 0x6f, 0x67, 0x5f, 0x70, 0x6f, 0x73, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06, 0x6c, 0x6f, 0x67, 0x50, 0x6f, 0x73, 0x12, 0x19, 0x0a,
	0x08, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x07, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x19,
	0x0a, 0x08, 0x69, 0x73, 0x5f, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x07, 0x69, 0x73, 0x54, 0x6f, 0x70, 0x69, 0x63, 0x12, 0x1f, 0x0a, 0x0b, 0x66, 0x69, 0x65,
	0x6c, 0x64, 0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a,
	0x66, 0x69, 0x65, 0x6c, 0x64, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x22, 0xa1, 0x01, 0x0a, 0x0b, 0x53,
	0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x44, 0x61, 0x74, 0x61, 0x12, 0x1b, 0x0a, 0x09, 0x62, 0x6c,
	0x6f, 0x63, 0x6b, 0x5f, 0x6e, 0x75, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x08, 0x62,
	0x6c, 0x6f, 0x63, 0x6b, 0x4e, 0x75, 0x6d, 0x12, 0x18, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65,
	0x73, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73,
	0x73, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x6c, 0x6f, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x73, 0x6c, 0x6f, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x31, 0x0a, 0x15, 0x73,
	0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x6a, 0x73, 0x6f, 0x6e,
	0x5f, 0x68, 0x65, 0x78, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x12, 0x73, 0x74, 0x6f, 0x72,
	0x61, 0x67, 0x65, 0x44, 0x61, 0x74, 0x61, 0x4a, 0x73, 0x6f, 0x6e, 0x48, 0x65, 0x78, 0x22, 0xdc,
	0x02, 0x0a, 0x0f, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x44, 0x61,
	0x74, 0x61, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x61, 0x73, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x68, 0x61, 0x73, 0x68, 0x12, 0x19, 0x0a, 0x08, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x5f,
	0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x49,
	0x64, 0x12, 0x1b, 0x0a, 0x09, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x6e, 0x75, 0x6d, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x04, 0x52, 0x08, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x4e, 0x75, 0x6d, 0x12, 0x14,
	0x0a, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04, 0x52, 0x05, 0x6e,
	0x6f, 0x6e, 0x63, 0x65, 0x12, 0x35, 0x0a, 0x18, 0x67, 0x61, 0x73, 0x5f, 0x74, 0x69, 0x70, 0x5f,
	0x63, 0x61, 0x70, 0x5f, 0x6f, 0x72, 0x5f, 0x67, 0x61, 0x73, 0x5f, 0x70, 0x72, 0x69, 0x63, 0x65,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x13, 0x67, 0x61, 0x73, 0x54, 0x69, 0x70, 0x43, 0x61,
	0x70, 0x4f, 0x72, 0x47, 0x61, 0x73, 0x50, 0x72, 0x69, 0x63, 0x65, 0x12, 0x1e, 0x0a, 0x0b, 0x67,
	0x61, 0x73, 0x5f, 0x66, 0x65, 0x65, 0x5f, 0x63, 0x61, 0x70, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x09, 0x67, 0x61, 0x73, 0x46, 0x65, 0x65, 0x43, 0x61, 0x70, 0x12, 0x1b, 0x0a, 0x09, 0x67,
	0x61, 0x73, 0x5f, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x18, 0x07, 0x20, 0x01, 0x28, 0x04, 0x52, 0x08,
	0x67, 0x61, 0x73, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x66, 0x72, 0x6f, 0x6d,
	0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x12, 0x0e, 0x0a, 0x02,
	0x74, 0x6f, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x74, 0x6f, 0x12, 0x14, 0x0a, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x12, 0x39, 0x0a, 0x19, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f,
	0x6e, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x5f, 0x6a, 0x73, 0x6f, 0x6e, 0x5f, 0x68, 0x65, 0x78, 0x18,
	0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x16, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x44, 0x61, 0x74, 0x61, 0x4a, 0x73, 0x6f, 0x6e, 0x48, 0x65, 0x78, 0x22, 0x2c, 0x0a,
	0x0b, 0x43, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x12, 0x1d, 0x0a, 0x0a,
	0x6a, 0x73, 0x6f, 0x6e, 0x5f, 0x62, 0x79, 0x74, 0x65, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x09, 0x6a, 0x73, 0x6f, 0x6e, 0x42, 0x79, 0x74, 0x65, 0x73, 0x22, 0x4c, 0x0a, 0x0e, 0x49,
	0x6e, 0x64, 0x65, 0x78, 0x65, 0x64, 0x52, 0x65, 0x63, 0x65, 0x69, 0x70, 0x74, 0x12, 0x14, 0x0a,
	0x05, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x69, 0x6e,
	0x64, 0x65, 0x78, 0x12, 0x24, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x10, 0x2e, 0x73, 0x64, 0x6b, 0x2e, 0x52, 0x65, 0x63, 0x65, 0x69, 0x70, 0x74, 0x44,
	0x61, 0x74, 0x61, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x22, 0x4c, 0x0a, 0x0e, 0x49, 0x6e, 0x64,
	0x65, 0x78, 0x65, 0x64, 0x53, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x69,
	0x6e, 0x64, 0x65, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x69, 0x6e, 0x64, 0x65,
	0x78, 0x12, 0x24, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x10, 0x2e, 0x73, 0x64, 0x6b, 0x2e, 0x53, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x44, 0x61, 0x74,
	0x61, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x22, 0x54, 0x0a, 0x12, 0x49, 0x6e, 0x64, 0x65, 0x78,
	0x65, 0x64, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x14, 0x0a,
	0x05, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x69, 0x6e,
	0x64, 0x65, 0x78, 0x12, 0x28, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x14, 0x2e, 0x73, 0x64, 0x6b, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x44, 0x61, 0x74, 0x61, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x22, 0x58, 0x0a,
	0x05, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x12, 0x39, 0x0a, 0x0c,
	0x63, 0x69, 0x72, 0x63, 0x75, 0x69, 0x74, 0x5f, 0x69, 0x6e, 0x66, 0x6f, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x16, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x41, 0x70, 0x70, 0x43,
	0x69, 0x72, 0x63, 0x75, 0x69, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0b, 0x63, 0x69, 0x72, 0x63,
	0x75, 0x69, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_sdk_types_proto_rawDescOnce sync.Once
	file_sdk_types_proto_rawDescData = file_sdk_types_proto_rawDesc
)

func file_sdk_types_proto_rawDescGZIP() []byte {
	file_sdk_types_proto_rawDescOnce.Do(func() {
		file_sdk_types_proto_rawDescData = protoimpl.X.CompressGZIP(file_sdk_types_proto_rawDescData)
	})
	return file_sdk_types_proto_rawDescData
}

var file_sdk_types_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_sdk_types_proto_goTypes = []interface{}{
	(*ReceiptData)(nil),                // 0: sdk.ReceiptData
	(*Field)(nil),                      // 1: sdk.Field
	(*StorageData)(nil),                // 2: sdk.StorageData
	(*TransactionData)(nil),            // 3: sdk.TransactionData
	(*CustomInput)(nil),                // 4: sdk.CustomInput
	(*IndexedReceipt)(nil),             // 5: sdk.IndexedReceipt
	(*IndexedStorage)(nil),             // 6: sdk.IndexedStorage
	(*IndexedTransaction)(nil),         // 7: sdk.IndexedTransaction
	(*Proof)(nil),                      // 8: sdk.Proof
	(*commonproto.AppCircuitInfo)(nil), // 9: common.AppCircuitInfo
}
var file_sdk_types_proto_depIdxs = []int32{
	1, // 0: sdk.ReceiptData.fields:type_name -> sdk.Field
	0, // 1: sdk.IndexedReceipt.data:type_name -> sdk.ReceiptData
	2, // 2: sdk.IndexedStorage.data:type_name -> sdk.StorageData
	3, // 3: sdk.IndexedTransaction.data:type_name -> sdk.TransactionData
	9, // 4: sdk.Proof.circuit_info:type_name -> common.AppCircuitInfo
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_sdk_types_proto_init() }
func file_sdk_types_proto_init() {
	if File_sdk_types_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_sdk_types_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ReceiptData); i {
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
		file_sdk_types_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Field); i {
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
		file_sdk_types_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StorageData); i {
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
		file_sdk_types_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TransactionData); i {
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
		file_sdk_types_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CustomInput); i {
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
		file_sdk_types_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IndexedReceipt); i {
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
		file_sdk_types_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IndexedStorage); i {
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
		file_sdk_types_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IndexedTransaction); i {
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
		file_sdk_types_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Proof); i {
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
			RawDescriptor: file_sdk_types_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_sdk_types_proto_goTypes,
		DependencyIndexes: file_sdk_types_proto_depIdxs,
		MessageInfos:      file_sdk_types_proto_msgTypes,
	}.Build()
	File_sdk_types_proto = out.File
	file_sdk_types_proto_rawDesc = nil
	file_sdk_types_proto_goTypes = nil
	file_sdk_types_proto_depIdxs = nil
}
