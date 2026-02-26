package dummy

import (
	"testing"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/test"
	"github.com/ethereum/go-ethereum/common"
)

func TestCircuit(t *testing.T) {
	rpc := "RPC_URL"
	outDir := "$HOME/circuitOut/myBrevisApp"
	app, err := sdk.NewBrevisApp(1, rpc, outDir)
	check(err)

	app.AddReceipt(sdk.ReceiptData{
		TxHash: common.HexToHash("7a129f9da761960a9209de1215b08709715cac842c34d9237a8d85de7da47da9"),
		Fields: []sdk.LogFieldData{
			{LogPos: 3, IsTopic: false, FieldIndex: 0},
			{LogPos: 3, IsTopic: true, FieldIndex: 2},
			{LogPos: 2, IsTopic: true, FieldIndex: 1},
		},
	})

	appCircuit := DefaultAppCircuit()
	appCircuitAssignment := DefaultAppCircuit()

	circuitInput, err := app.BuildCircuitInput(appCircuit)
	check(err)

	///////////////////////////////////////////////////////////////////////////////
	// Testing
	///////////////////////////////////////////////////////////////////////////////

	test.ProverSucceeded(t, appCircuit, appCircuitAssignment, circuitInput)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
