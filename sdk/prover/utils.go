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
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gowebpki/jcs"
	"google.golang.org/protobuf/encoding/protojson"
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

func buildFullAppCircuitInfo(app sdk.AppCircuit, in sdk.CircuitInput, vk, vkHash, witness string) *commonproto.AppCircuitInfo {
	inputCommitments := make([]string, len(in.InputCommitments))
	for i, value := range in.InputCommitments {
		inputCommitments[i] = fmt.Sprintf("0x%x", value)
	}

	toggles := make([]bool, len(in.Toggles()))
	for i, value := range in.Toggles() {
		toggles[i] = fmt.Sprintf("%x", value) == "1"
	}

	maxReceipts, maxStorage, maxTxs := app.Allocate()
	dataPoints := sdk.DataPointsNextPowerOf2(maxReceipts + maxStorage + maxTxs)

	return &commonproto.AppCircuitInfo{
		OutputCommitment:     hexutil.Encode(in.OutputCommitment.Hash().Bytes()),
		Vk:                   vk,
		InputCommitments:     inputCommitments,
		Toggles:              toggles,
		UseCallback:          true,
		Output:               hexutil.Encode(in.GetAbiPackedOutput()),
		VkHash:               vkHash,
		InputCommitmentsRoot: fmt.Sprintf("0x%x", in.InputCommitmentsRoot),
		Witness:              witness,
		MaxReceipts:          uint32(maxReceipts),
		MaxStorage:           uint32(maxStorage),
		MaxTx:                uint32(maxTxs),
		MaxNumDataPoints:     uint32(dataPoints),
	}
}

func buildPartialAppCircuitInfoForGatewayRequest(app sdk.AppCircuit, in *sdk.CircuitInput, vkHash string) *commonproto.AppCircuitInfo {
	toggles := make([]bool, len(in.Toggles()))
	for i, value := range in.Toggles() {
		toggles[i] = fmt.Sprintf("%x", value) == "1"
	}

	maxReceipts, maxStorage, maxTxs := app.Allocate()
	dataPoints := sdk.DataPointsNextPowerOf2(maxReceipts + maxStorage + maxTxs)

	return &commonproto.AppCircuitInfo{
		Toggles:          toggles,
		VkHash:           vkHash,
		MaxReceipts:      uint32(maxReceipts),
		MaxStorage:       uint32(maxStorage),
		MaxTx:            uint32(maxTxs),
		MaxNumDataPoints: uint32(dataPoints),
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
	fields := make([]sdk.LogFieldData, len(in.Fields))
	if len(in.Fields) == 0 {
		return sdk.ReceiptData{}, fmt.Errorf("invalid log field")
	}

	for i := range fields {
		field, err := convertProtoFieldToSdkLogField(in.Fields[i])
		if err != nil {
			return sdk.ReceiptData{}, err
		}
		fields[i] = field
	}

	return sdk.ReceiptData{
		TxHash: hex2Hash(in.TxHash),
		Fields: fields[:],
	}, nil
}

func convertProtoFieldToSdkLogField(in *sdkproto.Field) (sdk.LogFieldData, error) {
	return sdk.LogFieldData{
		LogPos:     uint(in.LogPos),
		IsTopic:    in.IsTopic,
		FieldIndex: uint(in.FieldIndex),
	}, nil
}

func convertProtoStorageToSdkStorage(in *sdkproto.StorageData) (sdk.StorageData, error) {
	return sdk.StorageData{
		BlockNum: new(big.Int).SetUint64(in.BlockNum),
		Address:  hex2Addr(in.Address),
		Slot:     hex2Hash(in.Slot),
	}, nil
}

func convertProtoTxToSdkTx(in *sdkproto.TransactionData) (sdk.TransactionData, error) {
	return sdk.TransactionData{
		Hash: hex2Hash(in.Hash),
	}, nil
}

func getProofId(vkHash string, req *sdkproto.ProveRequest) (string, error) {
	jsonBytes, err := protojson.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("protojson.Marshal err: %w", err)
	}
	canonJsonBytes, err := jcs.Transform(jsonBytes)
	if err != nil {
		return "", fmt.Errorf("jcs.Transform err: %w", err)
	}
	return crypto.Keccak256Hash(append([]byte(vkHash), canonJsonBytes...)).Hex(), nil
}

func getActiveJobsKey(vkHash string) string {
	return fmt.Sprintf("%s-%s", activeJobsKeyPrefix, vkHash)
}
