package twap

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

	EthUsdcPair := common.HexToAddress("0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc")

	app.AddStorage(sdk.StorageData{
		BlockNum: big.NewInt(19526368),
		Address:  EthUsdcPair,
		Slot:     common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000008"),
	})
	app.AddStorage(sdk.StorageData{
		BlockNum: big.NewInt(19526368),
		Address:  EthUsdcPair,
		Slot:     common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000009"),
	})
	app.AddStorage(sdk.StorageData{
		BlockNum: big.NewInt(19526368),
		Address:  EthUsdcPair,
		Slot:     common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000000a"),
	})

	app.AddStorage(sdk.StorageData{
		BlockNum: big.NewInt(19526488),
		Address:  EthUsdcPair,
		Slot:     common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000008"),
	})
	app.AddStorage(sdk.StorageData{
		BlockNum: big.NewInt(19526488),
		Address:  EthUsdcPair,
		Slot:     common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000009"),
	})
	app.AddStorage(sdk.StorageData{
		BlockNum: big.NewInt(19526488),
		Address:  EthUsdcPair,
		Slot:     common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000000a"),
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
