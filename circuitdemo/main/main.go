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
		Contract:   utils.Hex2Addr("0xec53bF9167f50cDEB3Ae105f56099aaaB9061F83"),
		LogIndex:   0,
		EventID:    utils.Hex2Hash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"),
		IsTopic:    false,
		FieldIndex: 0,
		Value:      utils.Hex2Hash("0x000000000000000000000000000000000000000000000000b5434e41ef93cdf9"),
	}

	logFieldData1 := sdk.LogFieldData{
		Contract:   utils.Hex2Addr("0xec53bF9167f50cDEB3Ae105f56099aaaB9061F83"),
		LogIndex:   0,
		EventID:    utils.Hex2Hash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"),
		IsTopic:    true,
		FieldIndex: 2,
		Value:      utils.Hex2Hash("0x0FB8b4981437C97F304097b899F4eBa3Aa01401A"),
	}

	receipt := sdk.ReceiptData{
		BlockNum:     new(big.Int).SetUint64(20861588),
		BlockBaseFee: new(big.Int).SetUint64(7343991989),
		TxHash:       utils.Hex2Hash("0xe1fa9bc29a1185125450fc8b0e588ec377e0d1c5acf66f0f66cac7124f6dba36"),
		Fields: [sdk.NumMaxLogFields]sdk.LogFieldData{
			logFieldData,
			logFieldData1,
		},
	}

	for i := 0; i < 3; i++ {
		app.AddReceipt(receipt, i*3)
	}

	for i := 0; i < 3; i++ {
		app.AddStorage(sdk.StorageData{
			BlockNum:     new(big.Int).SetUint64(20861588),
			BlockBaseFee: new(big.Int).SetUint64(7343991989),
			Address:      utils.Hex2Addr("0xec53bF9167f50cDEB3Ae105f56099aaaB9061F83"),
			Slot:         utils.Hex2Hash("0x0000000000000000000000000000000000000000000000000000000000000000"),
			Value:        utils.Hex2Hash("0x0000000000000000000000000000000000000000000000000000000000000001"),
		}, i+2)
	}

	for i := 0; i < 3; i++ {
		app.AddTransaction(sdk.TransactionData{
			BlockNum:     new(big.Int).SetUint64(20861588),
			BlockBaseFee: new(big.Int).SetUint64(7343991989),
			Hash:         utils.Hex2Hash("0xae934778e8f088c775d0b4350c06a66127456df8cf44a13b8c5566e974529194"),
			LeafHash:     utils.Hex2Hash("0x50a46fb905a23c119205ca313dbb2f4ce01cb43c344c5e378a19857fd5aa065e"),
		}, i*6)
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
