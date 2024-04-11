package prover

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/sdk/proto/commonproto"
	"github.com/brevis-network/brevis-sdk/sdk/proto/sdkproto"
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

func parseHash(encoded string) (common.Hash, error) {
	value, ok := new(big.Int).SetString(encoded, 0)
	if !ok {
		return common.Hash{}, fmt.Errorf("%s is not a valid value", value)
	}
	bs := value.Bytes()
	if len(bs) > 32 {
		return common.Hash{}, fmt.Errorf("%s exceeds 32 bytes", value)
	}
	return common.BytesToHash(bs), nil
}

func parseBig(encoded string) (*big.Int, error) {
	value, ok := new(big.Int).SetString(encoded, 0)
	if !ok {
		return nil, fmt.Errorf("%s is not a valid value", value)
	}
	bs := value.Bytes()
	if len(bs) > 32 {
		return nil, fmt.Errorf("%s exceeds 32 bytes", value)
	}
	return value, nil
}

func convertProtoReceiptToSdkReceipt(in *sdkproto.ReceiptData) (sdk.ReceiptData, error) {
	var fields [sdk.NumMaxLogFields]sdk.LogFieldData
	if len(in.Fields) == 0 {
		return sdk.ReceiptData{}, fmt.Errorf("invalid log field")
	}

	for i := range fields {
		if i < len(in.Fields) {
			field, err := convertProtoFieldToSdkLogField(in.Fields[i])
			if err != nil {
				return sdk.ReceiptData{}, err
			}
			fields[i] = field
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

func convertProtoFieldToSdkLogField(in *sdkproto.Field) (sdk.LogFieldData, error) {
	value, err := parseHash(in.Value)
	if err != nil {
		return sdk.LogFieldData{}, err
	}
	return sdk.LogFieldData{
		Contract:   hex2Addr(in.Contract),
		LogIndex:   uint(in.LogIndex),
		EventID:    hex2Hash(in.EventId),
		IsTopic:    in.IsTopic,
		FieldIndex: uint(in.FieldIndex),
		Value:      value,
	}, nil
}

func convertProtoStorageToSdkStorage(in *sdkproto.StorageData) (sdk.StorageData, error) {
	value, err := parseHash(in.Value)
	if err != nil {
		return sdk.StorageData{}, err
	}
	return sdk.StorageData{
		BlockNum: new(big.Int).SetUint64(in.BlockNum),
		Address:  hex2Addr(in.Address),
		Slot:     hex2Hash(in.Slot),
		Value:    value,
	}, nil
}

func convertProtoTxToSdkTx(in *sdkproto.TransactionData) (sdk.TransactionData, error) {
	value, err := parseBig(in.Value)
	if err != nil {
		return sdk.TransactionData{}, err
	}
	gasTipCapOrGasPrice, err := parseBig(in.GasTipCapOrGasPrice)
	if err != nil {
		return sdk.TransactionData{}, err
	}
	gasFeeCap, err := parseBig(in.GasFeeCap)
	if err != nil {
		return sdk.TransactionData{}, err
	}
	return sdk.TransactionData{
		Hash:                hex2Hash(in.Hash),
		ChainId:             new(big.Int).SetUint64(in.ChainId),
		BlockNum:            new(big.Int).SetUint64(in.BlockNum),
		Nonce:               in.Nonce,
		GasTipCapOrGasPrice: gasTipCapOrGasPrice,
		GasFeeCap:           gasFeeCap,
		GasLimit:            in.GasLimit,
		From:                hex2Addr(in.From),
		To:                  hex2Addr(in.To),
		Value:               value,
	}, nil
}
