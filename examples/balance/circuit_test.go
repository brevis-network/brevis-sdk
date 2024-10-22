package balance

import (
	"math/big"
	"testing"

	"github.com/brevis-network/brevis-sdk/sdk"
	"github.com/brevis-network/brevis-sdk/test"
	"github.com/ethereum/go-ethereum/common"
)

func TestCircuit(t *testing.T) {
	localDir := "$HOME/circuitOut/myBrevisApp/input"
	numMaxDataPoints := 128
	app, err := sdk.NewBrevisApp(1, numMaxDataPoints, "RPC_URL", localDir)
	check(err)

	USDT := common.HexToAddress("0xdac17f958d2ee523a2206206994597c13d831ec7")

	app.AddStorage(sdk.StorageData{
		BlockNum: big.NewInt(19290434),
		Address:  USDT,
		Slot:     common.HexToHash("0x568f97cb8c4c4a5582f76b76203c3168e6b403a6cad2536bcda6c6a37564ab52"),
	})

	app.AddStorage(sdk.StorageData{
		BlockNum: big.NewInt(19525436),
		Address:  USDT,
		Slot:     common.HexToHash("0x568f97cb8c4c4a5582f76b76203c3168e6b403a6cad2536bcda6c6a37564ab52"),
	})

	appCircuit := &AppCircuit{}
	appCircuitAssignment := &AppCircuit{}

	in, err := app.BuildCircuitInput(appCircuitAssignment)
	check(err)

	///////////////////////////////////////////////////////////////////////////////
	// Testing
	///////////////////////////////////////////////////////////////////////////////

	// Use the test package to check if the circuit can be solved using the given
	// assignment
	test.ProverSucceeded(t, appCircuit, appCircuitAssignment, in)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
