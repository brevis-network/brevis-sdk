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
	return nil
}

func main() {
	outDir := "$HOME/circuitOut/myBrevisApp"
	srsDir := "$HOME/kzgsrs"
	app, err := sdk.NewBrevisApp("localhost:11080")
	check(err)
	logFieldData := sdk.LogFieldData{
		Contract:   utils.Hex2Addr("0x397FF1542f962076d0BFE58eA045FfA2d347ACa0"),
		LogIndex:   12,
		EventID:    utils.Hex2Hash("0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822"),
		IsTopic:    false,
		FieldIndex: 3,
		Value:      utils.Hex2Hash("0x0000000000000000000000000000000000000000000000000000000000000000"),
	}

	receipt := sdk.ReceiptData{
		BlockNum: new(big.Int).SetUint64(20844438),
		TxHash:   utils.Hex2Hash("0xbc6709ddc1cc2dff10b1be86fcbefa416fe321a079b7e09a0b5ab5883d70604a"),
		Fields: [sdk.NumMaxLogFields]sdk.LogFieldData{
			logFieldData,
			logFieldData,
			logFieldData,
			logFieldData,
		},
	}

	for i := 0; i < 1; i++ {
		app.AddReceipt(receipt)
	}

	for i := 0; i < 1; i++ {
		app.AddStorage(sdk.StorageData{
			BlockNum: new(big.Int).SetUint64(20844438),
			Address:  utils.Hex2Addr("0x75231f58b43240c9718dd58b4967c5114342a86c"),
			Slot:     utils.Hex2Hash("0x0000000000000000000000000000000000000000000000000000000000000000"),
			Value:    utils.Hex2Hash("0x0000000000000000000000000000000000000000000000000000000000000001"),
		})
	}

	for i := 0; i < 1; i++ {
		app.AddTransaction(sdk.TransactionData{
			Hash:     utils.Hex2Hash("0x3aa1931426adbe23edbbf98f851023333876fd19fbf10743872e296bff2189a6"),
			LeafHash: utils.Hex2Hash("0x1e23a8df83fb904e7ab0c6e0a7fd3c70c007ed539a5d47a80d96a08d7bcf67ef"),
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
