package main

import (
	"math/big"
	"path/filepath"

	"github.com/brevis-network/brevis-sdk/common/utils"
	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/sdk/proto/gwproto"
	"github.com/ethereum/go-ethereum/common"
)

type AppCircuit struct{}

func (c *AppCircuit) Allocate() (maxReceipts, maxStorage, maxTransactions int) {
	// Our app is only ever going to use one storage data at a time so
	// we can simply limit the max number of data for storage to 1 and
	// 0 for all others
	return 32, 32, 64
}

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	api.OutputBool(sdk.ConstUint248(1))

	receipts := sdk.NewDataStream(api, in.Receipts)
	receipt := sdk.GetUnderlying(receipts, 0)
	api.OutputUint32(32, receipt.BlockNum)
	api.OutputAddress(receipt.Fields[0].Contract)
	return nil
}

func main() {
	outDir := "$HOME/circuitOut/myBrevisApp"
	srsDir := "$HOME/kzgsrs"
	app, err := sdk.NewBrevisApp(1, "localhost:11080")
	check(err)
	logFieldData := sdk.LogFieldData{
		Contract:   utils.Hex2Addr("0x4446e0f8417C1db113899929A8F3cEe8e0DcBCDb"),
		LogIndex:   0,
		EventID:    utils.Hex2Hash("0xfcc00a4bc74238c0d621a60c235a07a52789cca8e03b6e03f90d0b0c6e7bbecb"),
		IsTopic:    false,
		FieldIndex: 0,
		Value:      utils.Hex2Hash("0x0000000000000000000000000000000000000000000000000000000000000001"),
	}

	receipt := sdk.ReceiptData{
		BlockNum: new(big.Int).SetUint64(20861588),
		TxHash:   utils.Hex2Hash("0x3b762c2829801787b44ea8afba9510241014faa7dd86dbf03d729846aa346894"),
		Fields: [sdk.NumMaxLogFields]sdk.LogFieldData{
			logFieldData,
			logFieldData,
			logFieldData,
			logFieldData,
		},
	}

	for i := 0; i < 32; i++ {
		app.AddReceipt(receipt)
	}

	for i := 0; i < 32; i++ {
		app.AddStorage(sdk.StorageData{
			BlockNum: new(big.Int).SetUint64(20861588),
			Address:  utils.Hex2Addr("0x4446e0f8417C1db113899929A8F3cEe8e0DcBCDb"),
			Slot:     utils.Hex2Hash("0x0000000000000000000000000000000000000000000000000000000000000000"),
			Value:    utils.Hex2Hash("0x00000000000000000000000058b529f9084d7eaa598eb3477fe36064c5b7bbc1"),
		})
	}

	for i := 0; i < 64; i++ {
		app.AddTransaction(sdk.TransactionData{
			Hash:     utils.Hex2Hash("0x3b762c2829801787b44ea8afba9510241014faa7dd86dbf03d729846aa346894"),
			LeafHash: utils.Hex2Hash("0x72d15e4bf219afb31c502e2b24c9ae1d0c1b408cb8774706bfc48d6a2022b299"),
		})
	}

	appCircuitAssignment := &AppCircuit{}

	compiledCircuit, pk, vk, err := sdk.Compile(&AppCircuit{}, outDir, srsDir)
	check(err)
	circuitInput, err := app.BuildCircuitInput(appCircuitAssignment)
	check(err)
	witness, publicWitness, err := sdk.NewFullWitness(appCircuitAssignment, circuitInput)
	check(err)
	proof, err := sdk.Prove(compiledCircuit, pk, witness)
	check(err)
	err = sdk.WriteTo(proof, filepath.Join(outDir, "proof-"))
	check(err)
	err = sdk.Verify(vk, publicWitness, proof)
	check(err)

	appContract := common.HexToAddress("0xeec66d9b615ff84909be1cb1fe633cc26150417d")
	refundee := common.HexToAddress("0x1bF81EA1F2F6Afde216cD3210070936401A14Bd4")

	_, _, _, _, err = app.PrepareRequest(vk, witness, 1, 11155111, refundee, appContract, 400000, gwproto.QueryOption_ZK_MODE.Enum(), "", true)
	check(err)

	err = app.SubmitProof(proof)
	check(err)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
