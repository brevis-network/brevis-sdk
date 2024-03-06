package sdk

import (
	"fmt"
	"github.com/brevis-network/brevis-sdk/sdk/proto"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func buildAppCircuitInfo(in CircuitInput, vk plonk.VerifyingKey) *proto.AppCircuitInfo {
	inputCommitments := make([]string, len(in.InputCommitments))
	for i, value := range in.InputCommitments {
		inputCommitments[i] = fmt.Sprintf("0x%x", value)
	}

	toggles := make([]bool, len(in.Toggles()))
	for i, value := range in.Toggles() {
		toggles[i] = fmt.Sprintf("%x", value) == "1"
	}

	return &proto.AppCircuitInfo{
		OutputCommitment:  hexutil.Encode(in.OutputCommitment.Hash().Bytes()),
		Vk:                hexutil.Encode(mustWriteToBytes(vk)),
		InputCommitments:  inputCommitments,
		TogglesCommitment: fmt.Sprintf("0x%x", in.TogglesCommitment),
		Toggles:           toggles,
		UseCallback:       true,
		Output:            hexutil.Encode(in.dryRunOutput),
	}
}

func buildReceiptInfos(r rawData[ReceiptData], max int) (infos []*proto.ReceiptInfo) {
	for _, d := range r.list(max) {
		var logExtractInfo []*proto.LogExtractInfo
		for _, f := range d.Fields {
			logExtractInfo = append(logExtractInfo, &proto.LogExtractInfo{
				LogIndex:       uint64(f.LogIndex),
				ValueFromTopic: f.IsTopic,
				ValueIndex:     uint64(f.FieldIndex),
			})
		}
		infos = append(infos, &proto.ReceiptInfo{
			TransactionHash: d.TxHash.Hex(),
			LogExtractInfos: logExtractInfo,
		})
	}
	return
}

func buildStorageQueryInfos(r rawData[StorageData], max int) (infos []*proto.StorageQueryInfo) {
	for _, d := range r.list(max) {
		infos = append(infos, &proto.StorageQueryInfo{
			Account:     d.Address.Hex(),
			StorageKeys: []string{d.Key.Hex()},
			BlkNum:      d.BlockNum.Uint64(),
		})
	}
	return
}

func buildTxInfos(r rawData[TransactionData], max int) (infos []*proto.TransactionInfo) {
	for _, d := range r.list(max) {
		infos = append(infos, &proto.TransactionInfo{
			TransactionHash: d.Hash.Hex(),
		})
	}
	return
}
