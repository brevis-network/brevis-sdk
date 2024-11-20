package main

import (
	"math/big"

	"github.com/brevis-network/brevis-sdk/common/utils"
	"github.com/brevis-network/brevis-sdk/sdk"
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

	api.AssertInputsAreUnique()
	return nil
}

func main() {
	outDir := "$HOME/circuitOut/myBrevisApp"
	// srsDir := "$HOME/kzgsrs"
	rpc := ""
	app, err := sdk.NewBrevisApp(84532, rpc, outDir)
	check(err)
	logFieldData := sdk.LogFieldData{
		LogPos:     0,
		IsTopic:    false,
		FieldIndex: 0,
	}

	receipt := sdk.ReceiptData{
		TxHash: utils.Hex2Hash("0xdbd173cc246e7a9ee248984dad62dfa3a2727bdb3e49eac1e5d236b52a00946a"),
		Fields: []sdk.LogFieldData{
			logFieldData,
		},
	}

	app.AddReceipt(receipt)

	for i := 0; i < 1; i++ {
		app.AddStorage(sdk.StorageData{
			BlockNum: new(big.Int).SetUint64(18157312),
			Address:  utils.Hex2Addr("0xe48151964556381b33f93e05e36381fd53ec053e"),
			Slot:     utils.Hex2Hash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		})
	}

	for i := 0; i < 1; i++ {
		app.AddTransaction(sdk.TransactionData{
			Hash: utils.Hex2Hash("0xdbd173cc246e7a9ee248984dad62dfa3a2727bdb3e49eac1e5d236b52a00946a"),
		}, i)
	}

	appCircuitAssignment := &AppCircuit{}

	// compiledCircuit, pk, vk, _, err := sdk.Compile(&AppCircuit{}, outDir, srsDir)
	// check(err)
	circuitInput, err := app.BuildCircuitInput(appCircuitAssignment)
	check(err)
	_, _, err = sdk.NewFullWitness(appCircuitAssignment, circuitInput)
	check(err)
	// proof, err := sdk.Prove(compiledCircuit, pk, witness)
	// check(err)
	// err = sdk.WriteTo(proof, filepath.Join(outDir, "proof-"))
	// check(err)
	// err = sdk.Verify(vk, publicWitness, proof)
	// check(err)

	// appContract := common.HexToAddress("0xeec66d9b615ff84909be1cb1fe633cc26150417d")
	// refundee := common.HexToAddress("0x1bF81EA1F2F6Afde216cD3210070936401A14Bd4")

	// buf := bytes.NewBuffer([]byte{})
	// proof.WriteTo(buf)
	// fmt.Println("Proof: ", hexutil.Encode(buf.Bytes()))

	// _, _, _, _, err = app.PrepareRequest(vk, witness, 1, 421614, refundee, appContract, 400000, gwproto.QueryOption_ZK_MODE.Enum(), "")
	// check(err)

	// err = app.SubmitProof(proof)
	// check(err)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
