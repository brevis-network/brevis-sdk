package sdk

import (
	"fmt"

	"github.com/brevis-network/brevis-sdk/sdk/proto/commonproto"

	"github.com/brevis-network/brevis-sdk/sdk/proto/gwproto"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func buildAppCircuitInfo(in CircuitInput, vk plonk.VerifyingKey) *commonproto.AppCircuitInfo {
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
		Vk:                hexutil.Encode(mustWriteToBytes(vk)),
		InputCommitments:  inputCommitments,
		TogglesCommitment: fmt.Sprintf("0x%x", in.TogglesCommitment),
		Toggles:           toggles,
		UseCallback:       true,
		Output:            hexutil.Encode(in.dryRunOutput),
	}
}

func buildReceiptInfos(r rawData[ReceiptData], max int) (infos []*gwproto.ReceiptInfo) {
	for _, d := range r.list(max) {
		var logExtractInfo []*gwproto.LogExtractInfo
		for _, f := range d.Fields {
			if f.Contract.Cmp(common.Address{}) != 0 {
				logExtractInfo = append(logExtractInfo, &gwproto.LogExtractInfo{
					LogIndex:       uint64(f.LogIndex),
					ValueFromTopic: f.IsTopic,
					ValueIndex:     uint64(f.FieldIndex),
				})
			}
		}
		infos = append(infos, &gwproto.ReceiptInfo{
			TransactionHash: d.TxHash.Hex(),
			LogExtractInfos: logExtractInfo,
		})
	}
	return
}

func buildStorageQueryInfos(r rawData[StorageData], max int) (infos []*gwproto.StorageQueryInfo) {
	for _, d := range r.list(max) {
		infos = append(infos, &gwproto.StorageQueryInfo{
			Account:     d.Address.Hex(),
			StorageKeys: []string{d.Slot.Hex()},
			BlkNum:      d.BlockNum.Uint64(),
		})
	}
	return
}

func buildTxInfos(r rawData[TransactionData], max int) (infos []*gwproto.TransactionInfo) {
	for _, d := range r.list(max) {
		infos = append(infos, &gwproto.TransactionInfo{
			TransactionHash: d.Hash.Hex(),
		})
	}
	return
}
