package sdk

import (
	"fmt"
	"github.com/celer-network/brevis-sdk/sdk/proto"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func buildAppCircuitInfo(in PublicInput, vk plonk.VerifyingKey) *proto.AppCircuitInfo {
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

func buildReceiptInfos(qs queries[ReceiptQuery]) (infos []*proto.ReceiptInfo) {
	for _, query := range qs.list() {
		var logExtractInfo []*proto.LogExtractInfo
		for _, sub := range query.SubQueries {
			logExtractInfo = append(logExtractInfo, &proto.LogExtractInfo{
				LogIndex:       uint64(sub.LogIndex),
				ValueFromTopic: sub.IsTopic,
				ValueIndex:     uint64(sub.FieldIndex),
			})
		}
		infos = append(infos, &proto.ReceiptInfo{
			TransactionHash: query.TxHash.Hex(),
			LogExtractInfos: logExtractInfo,
		})
	}
	return
}

func buildStorageQueryInfos(qs queries[StorageQuery]) (infos []*proto.StorageQueryInfo) {
	for _, query := range qs.list() {
		infos = append(infos, &proto.StorageQueryInfo{
			Account:     query.Address.Hex(),
			StorageKeys: []string{query.Slot.Hex()},
			BlkNum:      uint64(query.BlockNum),
		})
	}
	return
}

func buildTxInfos(qs queries[TransactionQuery]) (infos []*proto.TransactionInfo) {
	for _, query := range qs.list() {
		infos = append(infos, &proto.TransactionInfo{
			TransactionHash: query.TxHash.Hex(),
		})
	}
	return
}
