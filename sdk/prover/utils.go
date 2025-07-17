package prover

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"

	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark/backend/witness"

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
	if in.ReceiptDataJsonHex != "" {
		bytes, decodeErr := hexutil.Decode(in.ReceiptDataJsonHex)
		if decodeErr != nil {
			fmt.Printf("Error decoding receipt %s data: %s\n", in.ReceiptDataJsonHex, decodeErr.Error())
			// try to use origin logic
		} else {
			var data sdk.ReceiptData
			err := json.Unmarshal(bytes, &data)
			if err != nil {
				fmt.Printf("Error decoding receipt %s data: %s\n", in.ReceiptDataJsonHex, err.Error())
				// try to use origin logic
			} else {
				log.Infof("receipt data is ready, no need to call rpc")
				return data, nil
			}
		}
	}
	log.Infof("receipt data not ready, call rpc now")

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
	if in.StorageDataJsonHex != "" {
		bytes, decodeErr := hexutil.Decode(in.StorageDataJsonHex)
		if decodeErr != nil {
			fmt.Printf("Error decoding storage %s data: %s\n", in.StorageDataJsonHex, decodeErr.Error())
			// try to use origin logic
		} else {
			var data sdk.StorageData
			err := json.Unmarshal(bytes, &data)
			if err != nil {
				fmt.Printf("Error decoding storage %s data: %s\n", in.StorageDataJsonHex, err.Error())
				// try to use origin logic
			} else {
				log.Infof("storage data is ready, no need to call rpc")
				return data, nil
			}
		}
	}
	log.Infof("storage data not ready, call rpc now")
	return sdk.StorageData{
		BlockNum: new(big.Int).SetUint64(in.BlockNum),
		Address:  hex2Addr(in.Address),
		Slot:     hex2Hash(in.Slot),
	}, nil
}

func convertProtoTxToSdkTx(in *sdkproto.TransactionData) (sdk.TransactionData, error) {
	if in.TransactionDataJsonHex != "" {
		bytes, decodeErr := hexutil.Decode(in.TransactionDataJsonHex)
		if decodeErr != nil {
			fmt.Printf("Error decoding transaction %s data: %s\n", in.TransactionDataJsonHex, decodeErr.Error())
			// try to use origin logic
		} else {
			var data sdk.TransactionData
			err := json.Unmarshal(bytes, &data)
			if err != nil {
				fmt.Printf("Error decoding transaction %s data: %s\n", in.TransactionDataJsonHex, err.Error())
				// try to use origin logic
			} else {
				log.Infof("receipt data is ready, no need to call rpc")
				return data, nil
			}
		}
	}
	log.Infof("transaction data not ready, call rpc now")
	return sdk.TransactionData{
		Hash: hex2Hash(in.Hash),
	}, nil
}

func newErr(code sdkproto.ErrCode, format string, args ...any) *sdkproto.Err {
	return &sdkproto.Err{
		Code: code,
		Msg:  fmt.Sprintf(format, args...),
	}
}

func buildInputStage1(appCircuit sdk.AppCircuit, brevisApp *sdk.BrevisApp, req *sdkproto.ProveRequest) (input *sdk.CircuitInput, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic, recovered value: %v", r)
		}
	}()

	// Add data
	for _, receipt := range req.Receipts {
		sdkReceipt, err := convertProtoReceiptToSdkReceipt(receipt.Data)
		if err != nil {
			return nil, fmt.Errorf("convertProtoReceiptToSdkReceipt err: %w", err)
		}
		brevisApp.AddReceipt(sdkReceipt, int(receipt.Index))
	}
	for _, storage := range req.Storages {
		sdkStorage, err := convertProtoStorageToSdkStorage(storage.Data)
		if err != nil {
			return nil, fmt.Errorf("convertProtoReceiptToSdkReceipt err: %w", err)
		}
		brevisApp.AddStorage(sdkStorage, int(storage.Index))
	}
	for _, transaction := range req.Transactions {
		sdkTx, err := convertProtoTxToSdkTx(transaction.Data)
		if err != nil {
			return nil, fmt.Errorf("convertProtoTxToSdkTx err: %w", err)
		}
		brevisApp.AddTransaction(sdkTx, int(transaction.Index))
	}
	inputStage1, err := brevisApp.BuildCircuitInputStage1(appCircuit)
	if err != nil {
		return nil, fmt.Errorf("BuildCircuitInputStage1 err: %w", err)
	}
	return &inputStage1, nil
}

func buildInputStage2(appCircuit sdk.AppCircuit, brevisApp *sdk.BrevisApp, req *sdkproto.ProveRequest, inputStage1 *sdk.CircuitInput) (*sdk.CircuitInput, sdk.AppCircuit, string, error) {
	guest, err := assignCustomInput(appCircuit, req.CustomInput)
	if err != nil {
		return nil, nil, "", fmt.Errorf("assignCustomInput err: %w", err)
	}

	input, err := brevisApp.BuildCircuitInputStage2(guest, *inputStage1)
	if err != nil {
		return nil, nil, "", fmt.Errorf("BuildCircuitInputStage2 err: %w", err)
	}

	_, publicWitness, err := sdk.NewFullWitness(guest, input)
	if err != nil {
		return nil, nil, "", fmt.Errorf("NewFullWitness err: %w", err)
	}

	var witnessBuffer bytes.Buffer
	witnessData := io.Writer(&witnessBuffer)
	_, err = publicWitness.WriteTo(witnessData)
	if err != nil {
		return nil, nil, "", fmt.Errorf("publicWitness.WriteTo err: %w", err)
	}
	witness := fmt.Sprintf("0x%x", witnessBuffer.Bytes())

	return &input, guest, witness, nil
}

func buildInput(appCircuit sdk.AppCircuit, brevisApp *sdk.BrevisApp, req *sdkproto.ProveRequest) (*sdk.CircuitInput, sdk.AppCircuit, string, *sdkproto.Err) {
	makeErr := func(code sdkproto.ErrCode, format string, args ...any) (*sdk.CircuitInput, sdk.AppCircuit, string, *sdkproto.Err) {
		log.Errorf(format, args...)
		log.Errorln()
		return nil, nil, "", newErr(code, format, args...)
	}

	inputStage1, err := buildInputStage1(appCircuit, brevisApp, req)
	if err != nil {
		return makeErr(sdkproto.ErrCode_ERROR_INVALID_INPUT, "buildInputStage1 err: %s", err.Error())
	}
	input, appCircuit, witness, err := buildInputStage2(appCircuit, brevisApp, req, inputStage1)
	if err != nil {
		return makeErr(sdkproto.ErrCode_ERROR_INVALID_INPUT, "buildInputStage2 err: %s", err.Error())
	}
	return input, appCircuit, witness, nil
}

func genWitness(input *sdk.CircuitInput, guest sdk.AppCircuit) (witness.Witness, witness.Witness, error) {
	witness, publicWitness, err := sdk.NewFullWitness(guest, *input)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get full witness: %w", err)
	}
	return witness, publicWitness, nil
}
