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
	return 63, 0, 0
}

func (c *AppCircuit) Define(api *sdk.CircuitAPI, in sdk.DataInput) error {
	return nil
}

func main() {

	outDir := "$HOME/circuitOut/myBrevisApp"
	srsDir := "$HOME/kzgsrs"
	app, err := sdk.NewBrevisApp()
	check(err)
	logFiledFata := sdk.LogFieldData{
		Contract:   utils.Hex2Addr("0x6A2AAd07396B36Fe02a22b33cf443582f682c82f"),
		LogIndex:   0,
		EventID:    utils.Hex2Hash("0x63373d1c4696214b898952999c9aaec57dac1ee2723cec59bea6888f489a9772"),
		IsTopic:    false,
		FieldIndex: 0,
		Value:      utils.Hex2Hash("0x201223A7DF4B8D523A2F74C71E10F2B01DAC1B9869A994566D820CCA1781838E"),
	}

	receipt := sdk.ReceiptData{
		BlockNum: new(big.Int).SetUint64(41759234),
		TxHash:   utils.Hex2Hash("0x6A2AAd07396B36Fe02a22b33cf443582f682c82f"),
		Fields: [sdk.NumMaxLogFields]sdk.LogFieldData{
			logFiledFata,
			logFiledFata,
			logFiledFata,
			logFiledFata,
			logFiledFata,
			logFiledFata,
			logFiledFata,
			logFiledFata,
		},
	}

	// TODO should not hardcode
	for i := 1; i < 16; i++ {
		app.AddReceipt(receipt, i)
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

	_, _, _, _, err = app.PrepareRequest(vk, 97, 97, refundee, appContract, 400000, gwproto.QueryOption_ZK_MODE.Enum(), "")
	check(err)

	err = app.SubmitProof(proof)
	check(err)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
