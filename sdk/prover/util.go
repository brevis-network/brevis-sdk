package prover

import (
	"encoding/hex"
	"fmt"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/sdk/proto/commonproto"
	"github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto"
	"github.com/celer-network/goutils/big"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// hex2Addr accepts hex string with or without 0x prefix and return Addr
func hex2Addr(s string) common.Address {
	return common.BytesToAddress(hex2Bytes(s))
}

func hex2Bytes(s string) (b []byte) {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	// hex.DecodeString expects an even-length string
	if len(s)%2 == 1 {
		s = "0" + s
	}
	b, _ = hex.DecodeString(s)
	return b
}

func hex2Hash(s string) common.Hash {
	return common.BytesToHash(hex2Bytes(s))
}

func buildAppCircuitInfo(in sdk.CircuitInput, vk string) *commonproto.AppCircuitInfo {
	inputCommitments := make([]string, len(in.InputCommitments))
	for i, value := range in.InputCommitments {
		inputCommitments[i] = fmt.Sprintf("0x%x", value)
	}

	toggles := make([]bool, len(in.Toggles()))
	for i, value := range in.Toggles() {
		toggles[i] = fmt.Sprintf("%x", value) == "1"
	}

	return &commonproto.AppCircuitInfo{
		OutputCommitment:  hexutil.Encode(in.OutputCommitment.Hash().Bytes()),
		Vk:                vk,
		InputCommitments:  inputCommitments,
		TogglesCommitment: fmt.Sprintf("0x%x", in.TogglesCommitment),
		Toggles:           toggles,
		UseCallback:       true,
		Output:            hexutil.Encode(in.GetAbiPackedOutput()),
	}
}

func convertProtoReceiptToSdkReceipt(in *sdkproto.ReceiptData) (sdk.ReceiptData, error) {
	var fields [sdk.NumMaxLogFields]sdk.LogFieldData
	if len(in.Fields) == 0 {
		return sdk.ReceiptData{}, fmt.Errorf("invalid log field")
	}

	for i := range fields {
		if i < len(in.Fields) {
			fields[i] = convertProtoFieldToSdkLog(in.Fields[i])
		} else {
			fields[i] = fields[len(in.Fields)-1]
		}
	}

	return sdk.ReceiptData{
		BlockNum: new(big.Int).SetUint64(in.BlockNum),
		TxHash:   hex2Hash(in.TxHash),
		Fields:   fields,
	}, nil
}

func convertProtoFieldToSdkLog(in *sdkproto.Field) sdk.LogFieldData {
	return sdk.LogFieldData{
		Contract:   hex2Addr(in.Contract),
		LogIndex:   uint(in.LogIndex),
		EventID:    hex2Hash(in.EventId),
		IsTopic:    in.IsTopic,
		FieldIndex: uint(in.FieldIndex),
		Value:      hex2Hash(in.Value),
	}
}

func convertProtoStorageToSdkStorage(in *sdkproto.StorageData) sdk.StorageData {
	return sdk.StorageData{
		BlockNum: new(big.Int).SetUint64(in.BlockNum),
		Address:  hex2Addr(in.Address),
		Slot:     hex2Hash(in.Slot),
		Value:    hex2Hash(in.Value),
	}
}

func convertProtoTxToSdkTx(in *sdkproto.TransactionData) sdk.TransactionData {
	return sdk.TransactionData{
		Hash:                hex2Hash(in.Hash),
		ChainId:             new(big.Int).SetUint64(in.ChainId),
		BlockNum:            new(big.Int).SetUint64(in.BlockNum),
		Nonce:               in.Nonce,
		GasTipCapOrGasPrice: new(big.Int).SetBytes(hex2Bytes(in.GasTipCapOrGasPrice)),
		GasFeeCap:           new(big.Int).SetBytes(hex2Bytes(in.GasFeeCap)),
		GasLimit:            in.GasLimit,
		From:                hex2Addr(in.From),
		To:                  hex2Addr(in.To),
		Value:               new(big.Int).SetBytes(hex2Bytes(in.Value)),
	}
}
