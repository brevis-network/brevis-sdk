package dummy

import (
	"math/big"
	"testing"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/test"
	"github.com/ethereum/go-ethereum/common"
)

func TestCircuit(t *testing.T) {
	numMaxDataPoints := 128
	app, err := sdk.NewBrevisApp(1, numMaxDataPoints, "RPC_URL")
	check(err)

	app.AddReceipt(sdk.ReceiptData{
		TxHash: common.HexToHash("53b37ec7975d217295f4bdadf8043b261fc49dccc16da9b9fc8b9530845a5794"),
		Fields: [sdk.NumMaxLogFields]sdk.LogFieldData{
			{LogPos: 3, IsTopic: false, FieldIndex: 0},
			{LogPos: 3, IsTopic: true, FieldIndex: 2},
			{LogPos: 2, IsTopic: true, FieldIndex: 1},
		},
	})
	app.AddStorage(sdk.StorageData{
		BlockNum: big.NewInt(19526368),
		Address:  common.HexToAddress("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc"),
		Slot:     common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000008"),
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
