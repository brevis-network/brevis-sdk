package sdk

import (
	"fmt"

	"github.com/brevis-network/brevis-sdk/sdk/proto/commonproto"

	"github.com/brevis-network/brevis-sdk/sdk/proto/gwproto"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func buildAppCircuitInfo(in CircuitInput,
	maxReceipts, maxStorage, maxTxs int,
	vk plonk.VerifyingKey, witness witness.Witness) (*commonproto.AppCircuitInfo, error) {
	inputCommitments := make([]string, len(in.InputCommitments))
	for i, value := range in.InputCommitments {
		inputCommitments[i] = fmt.Sprintf("0x%x", value)
	}

	toggles := make([]bool, len(in.Toggles()))
	for i, value := range in.Toggles() {
		toggles[i] = fmt.Sprintf("%x", value) == "1"
	}

	publicWitness, err := witness.Public()
	if err != nil {
		return nil, err
	}

	dataPoints := DataPointsNextPowerOf2(maxReceipts + maxStorage + maxTxs)

	return &commonproto.AppCircuitInfo{
		OutputCommitment:     hexutil.Encode(in.OutputCommitment.Hash().Bytes()),
		Vk:                   hexutil.Encode(mustWriteToBytes(vk)),
		InputCommitments:     inputCommitments,
		Toggles:              toggles,
		UseCallback:          true,
		Output:               hexutil.Encode(in.dryRunOutput),
		InputCommitmentsRoot: fmt.Sprintf("0x%x", in.InputCommitmentsRoot),
		Witness:              hexutil.Encode(mustWriteToBytes(publicWitness)),
		MaxReceipts:          uint32(maxReceipts),
		MaxStorage:           uint32(maxStorage),
		MaxTx:                uint32(maxTxs),
		MaxNumDataPoints:     uint32(dataPoints),
	}, nil
}

func buildReceiptInfos(r rawData[ReceiptData], max int) (infos []*gwproto.ReceiptInfo) {
	for _, d := range r.list(max) {
		var logExtractInfo []*gwproto.LogExtractInfo
		for _, f := range d.Fields {
			logExtractInfo = append(logExtractInfo, &gwproto.LogExtractInfo{
				LogPos:         uint64(f.LogPos),
				ValueFromTopic: f.IsTopic,
				ValueIndex:     uint64(f.FieldIndex),
			})
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
